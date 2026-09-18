//! VeloKVM host 控制面 — 剪貼簿傳輸服務（社群版 backend：TCP 9022 + Noise_IK）。
//!
//! 職責：監聽 TCP 9022 → Noise_IK 握手 → **Strict Whitelist** 驗證對端靜態公鑰
//! → 接收 `ClipboardMsg` 序列並重組 → 收到 `text/plain` 完成後以 `wl-copy`
//! 寫入本機 Wayland 剪貼簿（`--no-wl-copy` 關閉）。
//!
//! 剪貼簿**擷取**半場仍未接上：上游 lan-mouse `input-clipboard` crate 未問世，
//! 本機 Copy 不會同步出去。wl-copy 僅為橋接，上游 crate 落地後置換。
//! Wire 規格與傳輸語意見 `openspec/changes/clipboard-sync/`。
//!
//! License: GPL-3.0-or-later（本 crate 是 link 上游 lan-mouse GPL crates 的邊界）。

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process;
use std::thread;

use velokvm_proto::{
    ClipboardAssembler, ClipboardMsg, NoiseIkTcpChannel, NoiseIkTcpInitiator, DEFAULT_PORT,
    NOISE_PARAMS, SUPPORTED_MIME, MAX_TOTAL_LEN, MAX_CHUNK_LEN,
};

/// X25519 靜態私鑰長度。
const KEY_LEN: usize = 32;
/// Noise 握手訊息上限（IK 只有 2 個訊息，遠小於此）。
const MAX_HANDSHAKE_MSG: usize = 1024;

type Res<T> = Result<T, Box<dyn Error>>;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("genkey") => cmd_genkey(&args[1..]),
        Some("serve") => cmd_serve(&args[1..]),
        Some("push") => cmd_push(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(format!("未知子命令：{other}").into()),
    };
    if let Err(e) = result {
        eprintln!("錯誤：{e}");
        print_usage();
        process::exit(2);
    }
}

fn print_usage() {
    eprintln!(
        "VeloKVM 剪貼簿傳輸服務（社群版 backend：TCP {DEFAULT_PORT} + Noise_IK）

USAGE:
  velokvm-clipboard-service genkey --out <path>
  velokvm-clipboard-service serve  --key <path> [--listen <addr>]
                                   [--allow <file>] [--allow-key <hex>]... [--dump]
                                   [--no-wl-copy]
  velokvm-clipboard-service push   --peer <addr> --key <path> --peer-key <hex>
                                   (--text <text> | --file <path>)

genkey  產生 32-byte X25519 私鑰檔（0600），並印出對應公鑰 hex。
serve   監聽並服務剪貼簿傳輸；預設位址 0.0.0.0:{DEFAULT_PORT}。
        Strict Whitelist：未設定任何白名單即拒絕啟動（fail-closed）。
        --allow 檔格式：每行一個 32-byte hex 公鑰，`#` 之後為註解。
        --dump  印出收到的 payload 內容（預設只記錄長度，避免敏感內容入 log）。
        --no-wl-copy  收到完成的 text/plain 時不寫入本機剪貼簿
                      （預設以 wl-clipboard 橋接寫入 Wayland 剪貼簿）。
push    主動推送剪貼簿內容給對端（initiator）。
        --peer <addr>      對端位址（無 port 時補 {DEFAULT_PORT}）。
        --key <path>       本機私鑰檔（32 bytes，同 genkey 產生）。
        --peer-key <hex>   對端靜態公鑰 hex（32 bytes，必填）。
        --text <text>      要推送的文字內容（與 --file 二擇一）。
        --file <path>      要推送的檔案路徑（與 --text 二擇一）。
        內容以 Offer/Chunk/Complete 推送，超過 1 MiB 以 Abort 拒絕並非零退出。"
    );
}

/// `--name value`（單次）。
fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// `--name value`（可重複）。
fn opt_all(args: &[String], name: &str) -> Vec<String> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == name)
        .filter_map(|(i, _)| args.get(i + 1).cloned())
        .collect()
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn cmd_genkey(args: &[String]) -> Res<()> {
    let out = opt(args, "--out").ok_or("genkey 需要 --out <path>")?;
    let keypair = snow::Builder::new(NOISE_PARAMS.parse()?).generate_keypair()?;
    if keypair.private.len() != KEY_LEN {
        return Err("產生的私鑰長度非預期".into());
    }
    fs::write(&out, &keypair.private)?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;

    // ponytail: 公鑰另存 `<out>.pub`，讓 allow 檔可用 cat 串接，不必解析 stdout。
    let pub_path = format!("{out}.pub");
    fs::write(&pub_path, format!("{}\n", to_hex(&keypair.public)))?;

    println!("私鑰 → {out}（0600）");
    println!("公鑰 → {pub_path}（{}）", to_hex(&keypair.public));
    println!();
    println!("下一步：");
    println!("  1. 把 {pub_path} 交給對端，放進對方的 --allow");
    println!("  2. 把對端公鑰寫進本機 --allow 檔，然後 serve");
    Ok(())
}

fn cmd_serve(args: &[String]) -> Res<()> {
    let listen = opt(args, "--listen").unwrap_or_else(|| format!("0.0.0.0:{DEFAULT_PORT}"));
    let key_path = opt(args, "--key").ok_or("serve 需要 --key <path>（先用 genkey 產生）")?;
    let dump = flag(args, "--dump");
    let no_wl_copy = flag(args, "--no-wl-copy");

    let static_private = fs::read(&key_path)?;
    if static_private.len() != KEY_LEN {
        return Err(format!(
            "{key_path} 必須是 {KEY_LEN} bytes 的 X25519 私鑰（用 genkey 產生）"
        )
        .into());
    }

    let mut allow: HashSet<String> = HashSet::new();
    if let Some(path) = opt(args, "--allow") {
        for (lineno, line) in fs::read_to_string(&path)?.lines().enumerate() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            if from_hex(entry).map(|b| b.len()) != Some(KEY_LEN) {
                return Err(format!("{path}:{} 不是合法的 32-byte hex 公鑰", lineno + 1).into());
            }
            allow.insert(entry.to_ascii_lowercase());
        }
    }
    for key in opt_all(args, "--allow-key") {
        if from_hex(&key).map(|b| b.len()) != Some(KEY_LEN) {
            return Err(format!("--allow-key {key} 不是合法的 32-byte hex 公鑰").into());
        }
        allow.insert(key.to_ascii_lowercase());
    }

    // Strict Whitelist：無白名單不得啟動。
    if allow.is_empty() {
        return Err("未設定任何白名單（--allow <file> 或 --allow-key <hex>），拒絕啟動".into());
    }

    let listener = TcpListener::bind(&listen)?;
    println!("listening on {} (TCP)", listener.local_addr()?);
    println!("allowlist: {} 把公鑰", allow.len());
    println!("mime: {SUPPORTED_MIME} | 單筆上限 1 MiB | 單筆同時傳輸");
    if no_wl_copy {
        println!("wl-copy 橋接：關閉（--no-wl-copy），收到的 payload 僅記錄。");
    } else {
        println!("wl-copy 橋接：開啟 — 收到 text/plain 完成後寫入本機 Wayland 剪貼簿。");
    }
    io::stdout().flush().ok();

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let peer = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                let static_private = static_private.clone();
                let allow = allow.clone();
                thread::spawn(move || {
                    if let Err(e) =
                        serve_conn(stream, &static_private, &allow, dump, no_wl_copy, &peer)
                    {
                        eprintln!("[{peer}] 連線結束：{e}");
                    }
                });
            }
            Err(e) => eprintln!("accept 失敗：{e}"),
        }
    }
    Ok(())
}

/// 單一連線：Noise_IK responder 握手 → 白名單 → 接收／重組 → wl-copy 寫入。
fn serve_conn(
    mut stream: TcpStream,
    static_private: &[u8],
    allow: &HashSet<String>,
    dump: bool,
    no_wl_copy: bool,
    peer: &str,
) -> Res<()> {
    let builder = snow::Builder::new(NOISE_PARAMS.parse()?);
    let mut handshake = builder.local_private_key(static_private).build_responder()?;

    // Msg 1：initiator → responder（IK 0-RTT，內含 initiator 靜態公鑰）
    let msg1 = read_frame(&mut stream)?;
    let mut payload = [0u8; MAX_HANDSHAKE_MSG];
    handshake.read_message(&msg1, &mut payload)?;

    // 讀完 msg1 才學到對端靜態公鑰 → 這才是唯一可信的白名單檢查點
    let remote = handshake
        .get_remote_static()
        .map(to_hex)
        .ok_or("握手未提供對端靜態公鑰")?;
    if !allow.contains(&remote) {
        // 靜默丟棄：不回應 msg2，對端只會看到握手失敗
        eprintln!("[{peer}] 拒絕未授權節點 key={remote}");
        return Ok(());
    }

    // Msg 2：responder → initiator
    let mut msg2 = [0u8; MAX_HANDSHAKE_MSG];
    let n = handshake.write_message(&[], &mut msg2)?;
    write_frame(&mut stream, &msg2[..n])?;

    let transport = handshake.into_transport_mode()?;
    println!("[{peer}] ✅ Noise_IK 握手完成 key={remote}");

    let mut channel = NoiseIkTcpChannel::new(stream, transport);
    let mut assembler = ClipboardAssembler::new();
    let mut current_mime: Option<String> = None;

    loop {
        match channel.recv_msg() {
            Ok(ClipboardMsg::Offer {
                transfer_id,
                mime,
                total_len,
            }) => {
                assembler.offer(transfer_id, &mime, total_len)?;
                current_mime = Some(mime.clone());
                println!("[{peer}] offer #{transfer_id} {mime} {total_len} bytes");
            }
            Ok(ClipboardMsg::Chunk {
                transfer_id,
                seq,
                payload,
            }) => {
                assembler.push_chunk(transfer_id, seq, &payload)?;
            }
            Ok(ClipboardMsg::Complete { transfer_id }) => {
                let data = assembler.complete()?;
                let mime = current_mime.take().unwrap_or_else(|| SUPPORTED_MIME.to_string());
                println!(
                    "[{peer}] ✅ transfer #{transfer_id} 完成：{} bytes（{mime}）",
                    data.len()
                );
                if dump {
                    println!("----- payload -----\n{}\n-------------------", String::from_utf8_lossy(&data));
                }
                // 寫入本機剪貼簿（wl-clipboard 橋接；上游 input-clipboard 落地後置換）
                if !no_wl_copy && mime == SUPPORTED_MIME {
                    match write_clipboard_via_wl_copy(&data) {
                        Ok(()) => println!("[{peer}] 📋 已寫入本機 Wayland 剪貼簿（wl-copy）"),
                        Err(e) => eprintln!("[{peer}] ⚠️ wl-copy 寫入失敗：{e}"),
                    }
                }
            }
            Ok(ClipboardMsg::Abort { transfer_id, reason }) => {
                assembler.abort();
                current_mime = None;
                println!("[{peer}] abort #{transfer_id} reason={reason}");
            }
            Err(e) => {
                assembler.discard_all();
                println!("[{peer}] 連線結束：{e}");
                return Ok(());
            }
        }
    }
}

/// 以 `wl-copy` 橋接寫入本機 Wayland 剪貼簿（上游 `input-clipboard` 落地後置換）。
///
/// `wl-copy` 讀完 stdin 後自行 fork 常駐成為 selection source，parent 退出
/// 即代表寫入完成；預設 MIME 即 `text/plain;charset=utf-8`，與 `SUPPORTED_MIME` 一致。
fn write_clipboard_via_wl_copy(data: &[u8]) -> Res<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("無法啟動 wl-copy（需要 wl-clipboard 與 Wayland session）：{e}"))?;

    child
        .stdin
        .take()
        .ok_or("wl-copy stdin 不可用")?
        .write_all(data)
        .map_err(|e| format!("寫入 wl-copy stdin 失敗：{e}"))?;
    // drop stdin 讓 wl-copy 讀到 EOF；wait() 收割 fork 完成後的 parent
    child.wait().map_err(|e| format!("wl-copy 執行失敗：{e}"))?;
    Ok(())
}

/// 剪貼簿連出方：Noise_IK initiator → TCP 9022 → Offer/Chunk/Complete。
///
/// 參數：--peer <addr> --key <local-private> --peer-key <remote-public-hex>
///       --text <text> 或 --file <path>（恰好一個）。
fn cmd_push(args: &[String]) -> Res<()> {
    let peer = opt(args, "--peer").ok_or("push 需要 --peer <addr>")?;
    let key_path = opt(args, "--key").ok_or("push 需要 --key <path>")?;
    let peer_key = opt(args, "--peer-key").ok_or("push 需要 --peer-key <hex>")?;

    let text = opt(args, "--text");
    let file = opt(args, "--file");
    let data = match (text.as_ref(), file.as_ref()) {
        (Some(t), None) => t.as_bytes().to_vec(),
        (None, Some(p)) => {
            // 使用 File + Read::take 確保在讀取時強制限制大小，避免 TOCTOU
            let file = fs::File::open(p)?;
            let mut buffer = Vec::with_capacity(MAX_TOTAL_LEN + 1);
            let mut reader = file.take(MAX_TOTAL_LEN as u64 + 1);
            reader.read_to_end(&mut buffer)?;
            if buffer.len() > MAX_TOTAL_LEN {
                return Err(format!(
                    "檔案過大（{} bytes > 1 MiB），以 Abort 拒絕，不部分送出",
                    buffer.len()
                )
                .into());
            }
            // 驗證 UTF-8，因為 MIME 指定為 utf-8
            String::from_utf8(buffer.clone())
                .map_err(|_| Box::<dyn Error>::from("檔案不是有效的 UTF-8 文字"))?;
            buffer
        }
        (Some(_), Some(_)) => return Err("push 同時指定 --text 和 --file".into()),
        (None, None) => return Err("push 需指定 --text <text> 或 --file <path>".into()),
    };

    let local_private = fs::read(&key_path)?;
    if local_private.len() != KEY_LEN {
        return Err(format!("{key_path} 必須是 {KEY_LEN} bytes 的私鑰（用 genkey 產生）").into());
    }
    let remote_public = from_hex(&peer_key).ok_or_else(|| {
        format!("--peer-key {peer_key} 必須是合法的 32-byte hex")
    })?;
    if remote_public.len() != KEY_LEN {
        return Err(format!("--peer-key {peer_key} 必須是合法的 32-byte hex").into());
    }

    let addr = if peer.contains(':') {
        peer
    } else {
        format!("{peer}:{DEFAULT_PORT}")
    };

    let mut initiator = NoiseIkTcpInitiator::connect(&addr, &local_private, &remote_public)
        .map_err(|e| format!("連線失敗：{e}"))?;
    let mut channel = initiator
        .handshake()
        .map_err(|e| format!("Noise_IK 握手失敗：{e}"))?;

    let transfer_id = 1;

    if data.len() > MAX_TOTAL_LEN {
        channel
            .send_msg(&ClipboardMsg::Abort {
                transfer_id,
                reason: 1,
            })
            .map_err(|e| format!("推送 Abort 失敗：{e}"))?;
        return Err(format!(
            "內容逾限（{} bytes > 1 MiB），已送出 Abort reason=1",
            data.len()
        )
        .into());
    }

    channel
        .send_msg(&ClipboardMsg::Offer {
            transfer_id,
            mime: SUPPORTED_MIME.to_string(),
            total_len: data.len() as u64,
        })
        .map_err(|e| format!("推送 Offer 失敗：{e}"))?;

    for (seq, chunk) in data.chunks(MAX_CHUNK_LEN).enumerate() {
        channel
            .send_msg(&ClipboardMsg::Chunk {
                transfer_id,
                seq: seq as u32,
                payload: chunk.to_vec(),
            })
            .map_err(|e| format!("推送 Chunk #{seq} 失敗：{e}"))?;
    }

    channel
        .send_msg(&ClipboardMsg::Complete { transfer_id })
        .map_err(|e| format!("推送 Complete 失敗：{e}"))?;

    println!(
        "已送出 Complete，未取得接收端確認：{} bytes, {} chunk(s)",
        data.len(),
        data.len().div_ceil(MAX_CHUNK_LEN)
    );
    Ok(())
}

/// 握手訊息線上分框：`u16 BE` 長度前綴 + Noise 握手訊息。
///
/// 資料 frame 由 [`NoiseIkTcpChannel`] 以相同分框處理；對端實作見
/// `openspec/changes/clipboard-sync/design.md`。
fn read_frame(stream: &mut TcpStream) -> Res<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_HANDSHAKE_MSG {
        return Err(format!("握手 frame 長度不合理：{len}").into());
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Res<()> {
    if data.is_empty() || data.len() > MAX_HANDSHAKE_MSG {
        return Err("握手訊息長度不合理".into());
    }
    stream.write_all(&(data.len() as u16).to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        if i + 2 > s.len() {
            return None;
        }
        match u8::from_str_radix(&s[i..i + 2], 16) {
            Ok(byte) => result.push(byte),
            Err(_) => return None,
        }
    }
    Some(result)
}
