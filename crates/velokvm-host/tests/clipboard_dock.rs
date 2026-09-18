//! 對接 smoke test：證明 9022 端點「可被授權節點對接、拒絕未授權節點」。
//!
//! 這是使用者可見的 dock 契約：白名單內的 peer 完成 Noise_IK 握手並送出一筆
//! transfer；白名單外的 peer 在 msg2 就被切斷（不完成握手）。
//!
//! 以真實子行程 + 真實 TCP + 真實 Noise 握手驗證，不使用 mock。

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use snow::Builder;
use velokvm_proto::{ClipboardMsg, NoiseIkTcpChannel, NOISE_PARAMS, SUPPORTED_MIME};

const PAYLOAD: &[u8] = b"hello velokvm";

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), Box<dyn Error>> {
    stream.write_all(&(data.len() as u16).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Initiator 端握手（與 server 的 responder 分框對稱）。
fn initiator(
    addr: SocketAddr,
    my_private: &[u8],
    peer_public: &[u8],
) -> Result<NoiseIkTcpChannel, Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr)?;
    let mut handshake = Builder::new(NOISE_PARAMS.parse()?)
        .local_private_key(my_private)
        .remote_public_key(peer_public)
        .build_initiator()?;

    let mut buf = [0u8; 1024];
    let n = handshake.write_message(&[], &mut buf)?;
    write_frame(&mut stream, &buf[..n])?;

    // 未授權時 server 不回 msg2 → 這裡會拿到 EOF
    let msg2 = read_frame(&mut stream)?;
    let mut payload = [0u8; 1024];
    handshake.read_message(&msg2, &mut payload)?;

    Ok(NoiseIkTcpChannel::new(
        stream,
        handshake.into_transport_mode()?,
    ))
}

fn spawn_server(key: &Path, allow: &Path) -> (ServerGuard, SocketAddr, Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_velokvm-clipboard-service"))
        .args([
            "serve",
            "--key",
            key.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--allow",
            allow.to_str().unwrap(),
            "--no-wl-copy",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn velokvm-clipboard-service");

    let stdout = child.stdout.take().expect("server stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let addr = loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("server 未印出 listening 位址");
        if let Some(rest) = line.strip_prefix("listening on ") {
            break rest.trim_end_matches(" (TCP)").parse().expect("parse addr");
        }
    };

    (ServerGuard(child), addr, rx)
}

fn wait_for_line(rx: &Receiver<String>, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let line = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|_| panic!("等待 server 訊息「{needle}」逾時"));
        if line.contains(needle) {
            return;
        }
    }
}

#[test]
fn authorized_peer_docks_and_unauthorized_is_rejected() {
    let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
    let server = builder.generate_keypair().unwrap();
    let peer = builder.generate_keypair().unwrap();

    let dir: PathBuf = std::env::temp_dir().join(format!("velokvm-host-dock-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("server.key");
    let allow_path = dir.join("allow.txt");
    fs::write(&key_path, &server.private).unwrap();
    fs::write(&allow_path, format!("{}\n", hex(&peer.public))).unwrap();

    let (_guard, addr, rx) = spawn_server(&key_path, &allow_path);

    // 1) 未授權節點必須被拒：initiator 拿不到 msg2（EOF）
    let rogue = builder.generate_keypair().unwrap();
    let rogue_result = initiator(addr, &rogue.private, &server.public);
    assert!(
        rogue_result.is_err(),
        "白名單外的節點不得完成握手（Strict Whitelist 失效）"
    );

    // 2) 授權節點必須能對接並送出一筆完整 transfer
    let mut channel = initiator(addr, &peer.private, &server.public)
        .expect("白名單內的節點必須能完成 Noise_IK 握手");
    let transfer_id = 1;
    channel
        .send_msg(&ClipboardMsg::Offer {
            transfer_id,
            mime: SUPPORTED_MIME.to_string(),
            total_len: PAYLOAD.len() as u64,
        })
        .unwrap();
    channel
        .send_msg(&ClipboardMsg::Chunk {
            transfer_id,
            seq: 0,
            payload: PAYLOAD.to_vec(),
        })
        .unwrap();
    channel
        .send_msg(&ClipboardMsg::Complete { transfer_id })
        .unwrap();

    // 3) server 必須回報重組完成，且長度與送出一致
    wait_for_line(&rx, "✅ Noise_IK 握手完成");
    wait_for_line(&rx, &format!("✅ transfer #{transfer_id} 完成：{} bytes", PAYLOAD.len()));

    let _ = fs::remove_dir_all(&dir);
}

/// 無白名單時必須拒絕啟動（fail-closed）。
#[test]
fn serve_refuses_to_start_without_allowlist() {
    let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
    let server = builder.generate_keypair().unwrap();

    let dir = std::env::temp_dir().join(format!("velokvm-host-noallow-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let key_path = dir.join("server.key");
    fs::write(&key_path, &server.private).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_velokvm-clipboard-service"))
        .args([
            "serve",
            "--key",
            key_path.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .expect("run server");

    assert!(
        !output.status.success(),
        "沒有白名單時 serve 必須失敗（fail-closed）"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("白名單"),
        "錯誤訊息需說明缺少白名單，實際為：{stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
