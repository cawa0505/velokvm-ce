//! 剪貼簿 bulk 通道（Stage 1｜社群版 backend）：訊息層 + TCP + Noise_IK。
//!
//! 分層：[`ClipboardMsg`] codec（transport-agnostic）→ [`ClipboardAssembler`]（接收端
//! 重組）→ [`NoiseIkTcpChannel`]（TCP 9022 + Noise_IK 分框）。
//! 設計：`openspec/changes/clipboard-sync/design.md`。
//!
//! 注意：本模組與 fast-path 無關；Zero-Allocation 不變式僅約束 `RelMotionPacket`。

use snow::{HandshakeState, TransportState};
use std::io::{Read, Write};
use std::net::TcpStream;
use thiserror::Error;

use crate::NOISE_PARAMS;

const KEY_LEN: usize = 32;
pub const MAX_HANDSHAKE_MSG: usize = 1024;
/// 單筆 payload 上限：1 MiB（Phase 1 固定值，可組態語意）。
pub const MAX_TOTAL_LEN: usize = 1024 * 1024;
/// 單一 Chunk 上限：16 KiB。
pub const MAX_CHUNK_LEN: usize = 16 * 1024;
/// 社群版預設 port：TCP 9022（與 UDP 9021 fast-path 分離）。
pub const DEFAULT_PORT: u16 = 9022;
/// 單一加密 frame 上限：`u16` 長度前綴可表達的最大值（防寫入端截斷）。
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;
/// Phase 1 唯一支援的 MIME。
pub const SUPPORTED_MIME: &str = "text/plain;charset=utf-8";

/// 剪貼簿 bulk 通道錯誤。
#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Noise cryptographic error: {0}")]
    Crypto(#[from] snow::Error),
    /// codec 層畸形輸入。
    #[error("decode error: {0}")]
    Decode(&'static str),
    /// 超過大小上限。
    #[error("payload exceeds allowed size")]
    Oversize,
    /// 狀態機違規（transfer_id 不符、亂序、重複 offer 等）。
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// Phase 1 僅支援 [`SUPPORTED_MIME`]。
    #[error("mime not supported in phase 1")]
    UnsupportedMime,
}

/// 剪貼簿 bulk 訊息（Noise 加密前的明文語意）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardMsg {
    /// 宣告一次傳輸：MIME 與總長。
    Offer {
        transfer_id: u32,
        mime: String,
        total_len: u64,
    },
    /// 資料分塊，`seq` 自 0 遞增。
    Chunk {
        transfer_id: u32,
        seq: u32,
        payload: Vec<u8>,
    },
    /// 宣告分塊序列結束。
    Complete { transfer_id: u32 },
    /// 中止，接收端丟棄已收分塊。
    Abort { transfer_id: u32, reason: u8 },
}

const TYPE_OFFER: u8 = 1;
const TYPE_CHUNK: u8 = 2;
const TYPE_COMPLETE: u8 = 3;
const TYPE_ABORT: u8 = 4;

impl ClipboardMsg {
    /// 編碼為明文 bytes：`u8` 判別碼，整數 little-endian，mime 為 `u16` 長度 + UTF-8，
    /// payload 為 `u32` 長度 + bytes。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        match self {
            Self::Offer {
                transfer_id,
                mime,
                total_len,
            } => {
                out.push(TYPE_OFFER);
                out.extend_from_slice(&transfer_id.to_le_bytes());
                out.extend_from_slice(&(mime.len() as u16).to_le_bytes());
                out.extend_from_slice(mime.as_bytes());
                out.extend_from_slice(&total_len.to_le_bytes());
            }
            Self::Chunk {
                transfer_id,
                seq,
                payload,
            } => {
                out.push(TYPE_CHUNK);
                out.extend_from_slice(&transfer_id.to_le_bytes());
                out.extend_from_slice(&seq.to_le_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
            }
            Self::Complete { transfer_id } => {
                out.push(TYPE_COMPLETE);
                out.extend_from_slice(&transfer_id.to_le_bytes());
            }
            Self::Abort {
                transfer_id,
                reason,
            } => {
                out.push(TYPE_ABORT);
                out.extend_from_slice(&transfer_id.to_le_bytes());
                out.push(*reason);
            }
        }
        out
    }

    /// 解碼。畸形輸入一律回 [`ClipboardError::Decode`]，**不 panic**。
    pub fn decode(buf: &[u8]) -> Result<Self, ClipboardError> {
        let mut r = ByteReader::new(buf);
        match r.read_u8()? {
            TYPE_OFFER => {
                let transfer_id = r.read_u32()?;
                let mime_len = r.read_u16()? as usize;
                let mime = String::from_utf8(r.take_bytes(mime_len)?)
                    .map_err(|_| ClipboardError::Decode("mime not utf-8"))?;
                Ok(Self::Offer {
                    transfer_id,
                    mime,
                    total_len: r.read_u64()?,
                })
            }
            TYPE_CHUNK => {
                let transfer_id = r.read_u32()?;
                let seq = r.read_u32()?;
                let payload_len = r.read_u32()? as usize;
                Ok(Self::Chunk {
                    transfer_id,
                    seq,
                    payload: r.take_bytes(payload_len)?,
                })
            }
            TYPE_COMPLETE => Ok(Self::Complete {
                transfer_id: r.read_u32()?,
            }),
            TYPE_ABORT => Ok(Self::Abort {
                transfer_id: r.read_u32()?,
                reason: r.read_u8()?,
            }),
            _ => Err(ClipboardError::Decode("unknown message type")),
        }
    }
}

/// 邊界檢查的位元組讀取器：所有讀取先驗長度，畸形輸入回 `Err` 而非 panic。
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ClipboardError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(ClipboardError::Decode("offset overflow"))?;
        if end > self.buf.len() {
            return Err(ClipboardError::Decode("truncated"));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, ClipboardError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ClipboardError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, ClipboardError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ClipboardError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn take_bytes(&mut self, n: usize) -> Result<Vec<u8>, ClipboardError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ClipboardError::Decode("offset overflow"))?;
        if end > self.buf.len() {
            return Err(ClipboardError::Decode("truncated"));
        }
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }
}

/// 接收端重組狀態機：Phase 1 同時只允許一筆 transfer。
///
/// 語意：`offer` → `push_chunk` × n → `complete` 取回完整 payload；`abort` 丟棄一切。
#[derive(Debug, Default)]
pub struct ClipboardAssembler {
    transfer_id: Option<u32>,
    total_len: u64,
    next_seq: u32,
    buf: Vec<u8>,
}

impl ClipboardAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// 開始一筆 transfer。已有進行中、超限、或不支援的 MIME 皆回 `Err`。
    pub fn offer(
        &mut self,
        transfer_id: u32,
        mime: &str,
        total_len: u64,
    ) -> Result<(), ClipboardError> {
        if self.transfer_id.is_some() {
            return Err(ClipboardError::Protocol("transfer already in progress"));
        }
        if total_len > MAX_TOTAL_LEN as u64 {
            return Err(ClipboardError::Oversize);
        }
        if mime != SUPPORTED_MIME {
            return Err(ClipboardError::UnsupportedMime);
        }
        self.transfer_id = Some(transfer_id);
        self.total_len = total_len;
        self.next_seq = 0;
        self.buf.clear();
        Ok(())
    }

    /// 收一個分塊。無 offer、id 不符、亂序、超長、超出宣告總長皆回 `Err`。
    pub fn push_chunk(
        &mut self,
        transfer_id: u32,
        seq: u32,
        payload: &[u8],
    ) -> Result<(), ClipboardError> {
        let id = self
            .transfer_id
            .ok_or(ClipboardError::Protocol("no active transfer"))?;
        if id != transfer_id {
            return Err(ClipboardError::Protocol("transfer_id mismatch"));
        }
        if seq != self.next_seq {
            return Err(ClipboardError::Protocol("chunk out of order"));
        }
        if payload.len() > MAX_CHUNK_LEN {
            return Err(ClipboardError::Oversize);
        }
        if self.buf.len() + payload.len() > self.total_len as usize {
            return Err(ClipboardError::Protocol("chunks exceed declared total_len"));
        }
        self.buf.extend_from_slice(payload);
        self.next_seq += 1;
        Ok(())
    }

    /// 結束並取回完整 payload；未收滿回 `Err`。成功後狀態機歸零，可再接下一筆。
    pub fn complete(&mut self) -> Result<Vec<u8>, ClipboardError> {
        if self.transfer_id.is_none() {
            return Err(ClipboardError::Protocol("no active transfer"));
        }
        if self.buf.len() != self.total_len as usize {
            return Err(ClipboardError::Protocol("incomplete transfer"));
        }
        self.transfer_id = None;
        self.total_len = 0;
        self.next_seq = 0;
        Ok(std::mem::take(&mut self.buf))
    }

    /// 中止並丟棄已收分塊。
    pub fn abort(&mut self) {
        *self = Self::default();
    }

    /// 連線中斷等情境的全量丟棄。
    pub fn discard_all(&mut self) {
        self.abort();
    }
}

/// 社群版 backend：專用 TCP 9022 + Noise_IK，`u16 BE` 長度前綴分框。
///
/// TCP 有序可靠，故**不做** anti-replay（重放需重新握手，即得新金鑰）；反壓交由 TCP 流控。
pub struct NoiseIkTcpChannel {
    stream: TcpStream,
    transport: TransportState,
}

impl NoiseIkTcpChannel {
    pub fn new(stream: TcpStream, transport: TransportState) -> Self {
        Self { stream, transport }
    }

    /// encode → Noise 加密 → `u16 BE` 密文長度前綴 → write_all。
    ///
    /// `ponytail:` 每訊息一次配置；bulk 路徑允許，若 profiling 顯示熱點再拉高 scratch buffer。
    pub fn send_msg(&mut self, msg: &ClipboardMsg) -> Result<(), ClipboardError> {
        let plaintext = msg.encode();
        let mut ciphertext = vec![0u8; plaintext.len() + 16]; // Poly1305 tag
        let n = self.transport.write_message(&plaintext, &mut ciphertext)?;
        if n > MAX_FRAME_LEN {
            return Err(ClipboardError::Oversize);
        }
        self.stream.write_all(&(n as u16).to_be_bytes())?;
        self.stream.write_all(&ciphertext[..n])?;
        self.stream.flush()?;
        Ok(())
    }

    /// 讀 `u16 BE` 長度 → read_exact 密文 → Noise 解密 → decode。
    pub fn recv_msg(&mut self) -> Result<ClipboardMsg, ClipboardError> {
        let mut len_buf = [0u8; 2];
        self.stream.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(ClipboardError::Protocol("empty frame"));
        }
        let mut ciphertext = vec![0u8; len];
        self.stream.read_exact(&mut ciphertext)?;
        let mut plaintext = vec![0u8; len];
        let n = self.transport.read_message(&ciphertext, &mut plaintext)?;
        ClipboardMsg::decode(&plaintext[..n])
    }
}

/// 社群版 backend 的連出方：TCP 連線 + Noise_IK 握手。
pub struct NoiseIkTcpInitiator {
    stream: Option<TcpStream>,
    handshake: Option<HandshakeState>,
}

impl NoiseIkTcpInitiator {
    /// 建立 TCP 連線並準備 0-RTT Noise_IK 握手。
    ///
    /// TCP 連線本身是網路 IO，但此函數不執行任何 Noise 訊息交換；
    /// 握手在 [`NoiseIkTcpInitiator::handshake`] 才完成。
    pub fn connect(
        addr: &str,
        local_private: &[u8],
        remote_public: &[u8],
    ) -> Result<Self, ClipboardError> {
        if local_private.len() != KEY_LEN {
            return Err(ClipboardError::Protocol("local private key must be 32 bytes"));
        }
        if remote_public.len() != KEY_LEN {
            return Err(ClipboardError::Protocol("remote public key must be 32 bytes"));
        }
        let stream = TcpStream::connect(addr)?;
        let builder = snow::Builder::new(NOISE_PARAMS.parse()?);
        let handshake = builder
            .local_private_key(local_private)
            .remote_public_key(remote_public)
            .build_initiator()?;
        Ok(Self {
            stream: Some(stream),
            handshake: Some(handshake),
        })
    }

    /// 寫入 msg1、讀取 msg2、進入 transport mode，並回傳既有 `NoiseIkTcpChannel`。
    pub fn handshake(&mut self) -> Result<NoiseIkTcpChannel, ClipboardError> {
        let mut stream = self
            .stream
            .take()
            .ok_or(ClipboardError::Protocol("initiator stream already taken"))?;
        let mut handshake = self
            .handshake
            .take()
            .ok_or(ClipboardError::Protocol("initiator handshake already taken"))?;

        let mut buf = [0u8; 256];
        let mut payload = [0u8; 256];
        let n = handshake.write_message(b"", &mut buf)?;
        write_frame(&mut stream, &buf[..n])?;
        let msg2 = read_frame(&mut stream)?;
        handshake.read_message(&msg2, &mut payload)?;
        let transport = handshake.into_transport_mode()?;
        Ok(NoiseIkTcpChannel::new(stream, transport))
    }
}

/// `u16 BE` 長度前綴，與 [`NoiseIkTcpChannel`] 內部使用對稱。
pub fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, ClipboardError> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_MSG {
        return Err(ClipboardError::Decode("invalid frame length"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), ClipboardError> {
    if data.is_empty() || data.len() > MAX_HANDSHAKE_MSG {
        return Err(ClipboardError::Oversize);
    }
    stream.write_all(&(data.len() as u16).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::NOISE_PARAMS;
    use snow::Builder;
    use std::collections::HashSet;
    use std::net::TcpListener;
    use std::thread;

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 完成 Noise_IK 0-RTT 握手（與 lib.rs 的 fast-path e2e 測試同寫法），
    /// 回傳 (initiator, responder) 的 TransportState。
    fn handshake_pair() -> (TransportState, TransportState) {
        let builder_init = Builder::new(NOISE_PARAMS.parse().unwrap());
        let builder_resp = Builder::new(NOISE_PARAMS.parse().unwrap());

        let static_init = builder_init.generate_keypair().unwrap();
        let static_resp = builder_resp.generate_keypair().unwrap();

        let mut initiator = builder_init
            .local_private_key(&static_init.private)
            .remote_public_key(&static_resp.public) // IK：initiator 預知 responder 靜態公鑰
            .build_initiator()
            .unwrap();
        let mut responder = builder_resp
            .local_private_key(&static_resp.private)
            .build_responder()
            .unwrap();

        let mut msg = [0u8; 256];
        let mut payload = [0u8; 256];

        let n = initiator.write_message(b"", &mut msg).unwrap();
        responder.read_message(&msg[..n], &mut payload).unwrap();

        let n = responder.write_message(b"", &mut msg).unwrap();
        initiator.read_message(&msg[..n], &mut payload).unwrap();

        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    fn codec_roundtrip(msg: ClipboardMsg) {
        let buf = msg.encode();
        assert_eq!(ClipboardMsg::decode(&buf).unwrap(), msg);
    }

    #[test]
    fn test_codec_roundtrip_all_variants() {
        codec_roundtrip(ClipboardMsg::Offer {
            transfer_id: 7,
            mime: SUPPORTED_MIME.to_string(),
            total_len: 11,
        });
        codec_roundtrip(ClipboardMsg::Chunk {
            transfer_id: 7,
            seq: 0,
            payload: b"hello ".to_vec(),
        });
        codec_roundtrip(ClipboardMsg::Complete { transfer_id: 7 });
        codec_roundtrip(ClipboardMsg::Abort {
            transfer_id: 7,
            reason: 1,
        });
    }

    #[test]
    fn test_decode_rejects_malformed() {
        assert!(ClipboardMsg::decode(&[]).is_err());
        assert!(ClipboardMsg::decode(&[0x99]).is_err()); // 未知型別
        assert!(ClipboardMsg::decode(&[TYPE_OFFER]).is_err()); // 截斷
        assert!(
            ClipboardMsg::decode(&[TYPE_OFFER, 7, 0, 0, 0, 0xff, 0xff]).is_err(),
            "mime 長度謊報必須被拒"
        );
    }

    #[test]
    fn test_assembler_normal_path() {
        let mut a = ClipboardAssembler::new();
        a.offer(1, SUPPORTED_MIME, 11).unwrap();
        a.push_chunk(1, 0, b"hello ").unwrap();
        a.push_chunk(1, 1, b"world").unwrap();
        assert_eq!(a.complete().unwrap(), b"hello world".to_vec());
    }

    #[test]
    fn test_assembler_rejects_oversize_and_bad_mime() {
        let mut a = ClipboardAssembler::new();
        assert!(matches!(
            a.offer(1, SUPPORTED_MIME, MAX_TOTAL_LEN as u64 + 1),
            Err(ClipboardError::Oversize)
        ));
        assert!(matches!(
            a.offer(1, "image/png", 4),
            Err(ClipboardError::UnsupportedMime)
        ));
    }

    #[test]
    fn test_assembler_rejects_bad_chunks() {
        let mut a = ClipboardAssembler::new();
        assert!(a.push_chunk(1, 0, b"ab").is_err(), "無 offer 就收 chunk");

        a.offer(1, SUPPORTED_MIME, 4).unwrap();
        assert!(a.push_chunk(2, 0, b"ab").is_err(), "transfer_id 不符");
        assert!(
            a.push_chunk(1, 0, &vec![0u8; MAX_CHUNK_LEN + 1]).is_err(),
            "超過單 chunk 上限"
        );
        assert!(a.push_chunk(1, 5, b"ab").is_err(), "亂序");
        assert!(a.push_chunk(1, 0, b"abcde").is_err(), "超出宣告總長");
        assert!(a.complete().is_err(), "未收滿不得完成");

        a.push_chunk(1, 0, b"abcd").unwrap();
        assert_eq!(a.complete().unwrap(), b"abcd".to_vec());
    }

    #[test]
    fn test_assembler_abort_and_reuse() {
        let mut a = ClipboardAssembler::new();
        a.offer(1, SUPPORTED_MIME, 4).unwrap();
        a.push_chunk(1, 0, b"ab").unwrap();
        a.abort();

        // abort 後狀態歸零，可再接下一筆
        a.offer(2, SUPPORTED_MIME, 2).unwrap();
        a.push_chunk(2, 0, b"ok").unwrap();
        assert_eq!(a.complete().unwrap(), b"ok".to_vec());
    }

    #[test]
    fn test_assembler_rejects_concurrent_transfer() {
        let mut a = ClipboardAssembler::new();
        a.offer(1, SUPPORTED_MIME, 4).unwrap();
        assert!(a.offer(2, SUPPORTED_MIME, 4).is_err());
    }

    /// E2E：真實 Noise_IK 握手 + TCP loopback 傳輸完整 transfer。
    #[test]
    fn test_tcp_noise_channel_e2e() {
        let (tx_state, rx_state) = handshake_pair();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ch = NoiseIkTcpChannel::new(stream, rx_state);
            let mut asm = ClipboardAssembler::new();

            match ch.recv_msg().unwrap() {
                ClipboardMsg::Offer {
                    transfer_id,
                    mime,
                    total_len,
                } => asm.offer(transfer_id, &mime, total_len).unwrap(),
                other => panic!("expected Offer, got {other:?}"),
            }
            for _ in 0..2 {
                match ch.recv_msg().unwrap() {
                    ClipboardMsg::Chunk {
                        transfer_id,
                        seq,
                        payload,
                    } => asm.push_chunk(transfer_id, seq, &payload).unwrap(),
                    other => panic!("expected Chunk, got {other:?}"),
                }
            }
            match ch.recv_msg().unwrap() {
                ClipboardMsg::Complete { transfer_id } => {
                    assert_eq!(transfer_id, 9);
                }
                other => panic!("expected Complete, got {other:?}"),
            }
            asm.complete().unwrap()
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut ch = NoiseIkTcpChannel::new(stream, tx_state);
        ch.send_msg(&ClipboardMsg::Offer {
            transfer_id: 9,
            mime: SUPPORTED_MIME.to_string(),
            total_len: 11,
        })
        .unwrap();
        ch.send_msg(&ClipboardMsg::Chunk {
            transfer_id: 9,
            seq: 0,
            payload: b"hello ".to_vec(),
        })
        .unwrap();
        ch.send_msg(&ClipboardMsg::Chunk {
            transfer_id: 9,
            seq: 1,
            payload: b"world".to_vec(),
        })
        .unwrap();
        ch.send_msg(&ClipboardMsg::Complete { transfer_id: 9 })
            .unwrap();

        assert_eq!(server.join().unwrap(), b"hello world".to_vec());
    }

    /// 產生一組金鑰對，回傳 (private, public)。
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let kp = builder.generate_keypair().unwrap();
        (kp.private, kp.public)
    }

    /// 測試情境：responder 白名單含 initiator 公鑰 → 握手成功。
    #[test]
    fn test_initiator_authorized_handshake() {
        let (init_priv, init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let allow: HashSet<String> = std::iter::once(to_hex(&init_pub)).collect();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
            let mut handshake = builder.local_private_key(&resp_priv).build_responder().unwrap();
            let msg1 = read_frame(&mut stream).unwrap();
            let mut payload = [0u8; 256];
            handshake.read_message(&msg1, &mut payload).unwrap();
            let remote = to_hex(handshake.get_remote_static().unwrap());
            assert!(allow.contains(&remote), "白名單未包含 initiator 公鑰");
            let mut msg2 = [0u8; 256];
            let n = handshake.write_message(&[], &mut msg2).unwrap();
            write_frame(&mut stream, &msg2[..n]).unwrap();
            let transport = handshake.into_transport_mode().unwrap();
            let mut ch = NoiseIkTcpChannel::new(stream, transport);
            let msg = ch.recv_msg().unwrap();
            assert!(matches!(msg, ClipboardMsg::Complete { .. }));
        });

        let mut initiator = NoiseIkTcpInitiator::connect(
            &addr.to_string(),
            &init_priv,
            &resp_pub,
        )
        .unwrap();
        let mut ch = initiator.handshake().unwrap();
        ch.send_msg(&ClipboardMsg::Complete { transfer_id: 1 })
            .unwrap();

        server.join().unwrap();
    }

    /// 測試情境：responder 白名單不含 initiator 公鑰 → 握手失敗。
    #[test]
    fn test_initiator_unauthorized_handshake() {
        let (init_priv, _init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // 白名單放的是另一把公鑰，不是 initiator 的
        let (_, other_pub) = keypair();
        let allow: HashSet<String> = std::iter::once(to_hex(&other_pub)).collect();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
            let mut handshake = builder.local_private_key(&resp_priv).build_responder().unwrap();
            let msg1 = read_frame(&mut stream).unwrap();
            let mut payload = [0u8; 256];
            handshake.read_message(&msg1, &mut payload).unwrap();
            let remote = to_hex(handshake.get_remote_static().unwrap());
            assert!(!allow.contains(&remote), "白名單不應包含 initiator 公鑰");
            // 靜默丟棄：不回應 msg2，對端只會看到握手失敗
            drop(stream);
        });

        let mut initiator = NoiseIkTcpInitiator::connect(
            &addr.to_string(),
            &init_priv,
            &resp_pub,
        )
        .unwrap();
        let result = initiator.handshake();
        assert!(result.is_err(), "未授權節點不應完成握手");

        server.join().unwrap();
    }

    /// 測試情境：畸形分框被拒（確定性版本）。
    ///
    /// server 先完整讀取 initiator 的 msg1 再寫入畸形長度前綴，
    /// 因此 initiator 的失敗必定來自 frame 長度檢查，而不是競爭性的 IO 錯誤。
    #[test]
    fn test_initiator_rejects_malformed_frame() {
        let (init_priv, _init_pub) = keypair();
        let (resp_priv, resp_pub) = keypair();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // 先完整吃下 msg1，消除寫入競爭
            let msg1 = read_frame(&mut stream).unwrap();
            // 驗證 msg1 是合法 Noise 訊息（用真正的 responder 私鑰解密；不轉入 transport）
            let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
            let mut handshake = builder
                .local_private_key(&resp_priv)
                .build_responder()
                .unwrap();
            let mut payload = [0u8; MAX_HANDSHAKE_MSG];
            handshake
                .read_message(&msg1, &mut payload)
                .expect("msg1 應為合法 Noise 訊息");

            // 同一連線上寫入長度前綴 0：確定性觸發 Decode
            use std::io::Write as _;
            stream.write_all(&[0x00, 0x00]).unwrap();
            // 等 initiator 讀到 frame 並失敗後才結束，避免過早 drop 造成 IO 錯誤
            thread::sleep(std::time::Duration::from_millis(200));
        });

        let mut initiator =
            NoiseIkTcpInitiator::connect(&addr.to_string(), &init_priv, &resp_pub).unwrap();
        let result = initiator.handshake();
        match result {
            Err(e) => assert!(
                matches!(e, ClipboardError::Decode(_)),
                "畸形 frame 應回 Decode，實際：{e}"
            ),
            Ok(_) => panic!("畸形 frame 應導致握手失敗"),
        }

        server.join().unwrap();
    }

    /// 測試情境：connect 時私鑰長度不對。
    #[test]
    fn test_initiator_connect_rejects_bad_key_length() {
        let (_, resp_pub) = keypair();
        let bad_priv = vec![0u8; 16];
        let result = NoiseIkTcpInitiator::connect("127.0.0.1:1", &bad_priv, &resp_pub);
        assert!(matches!(result, Err(ClipboardError::Protocol(_))));
    }
}
