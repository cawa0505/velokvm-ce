pub mod protocol;
pub mod anti_replay;
pub mod transport;
pub mod clipboard;

pub use protocol::{ButtonFlags, PacketTag, RelMotionPacket, REL_MOTION_SIZE};
pub use anti_replay::AntiReplayWindow;
pub use transport::{ChannelError, NoiseIkUdpChannel};
pub use clipboard::{
    ClipboardAssembler, ClipboardError, ClipboardMsg, NoiseIkTcpChannel, NoiseIkTcpInitiator,
    DEFAULT_PORT, MAX_CHUNK_LEN, MAX_TOTAL_LEN, SUPPORTED_MIME, MAX_HANDSHAKE_MSG,
};

/// Noise_IK 參數字串：fast-path（UDP 9021）、剪貼簿 bulk（TCP 9022）與 host 服務共用的單一真實來源。
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Builder;
    use std::net::UdpSocket;
    use std::time::Instant;

    #[test]
    fn test_packet_bitpacking_zero_copy() {
        let mut flags = ButtonFlags::default();
        flags.set(ButtonFlags::BTN_LEFT);
        flags.set(ButtonFlags::BTN_EXTRA);

        let pkt = RelMotionPacket::new(1001, 500234, -25, 42, 1, -1, flags);
        assert_eq!(std::mem::size_of::<RelMotionPacket>(), 16);
        assert_eq!(REL_MOTION_SIZE, 16);

        let bytes = pkt.as_bytes();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], PacketTag::RelMotion as u8);

        // 零拷貝反序列化
        let decoded = RelMotionPacket::from_bytes(bytes).expect("Valid decode");
        assert_eq!(decoded.sequence(), 1001);
        assert_eq!(decoded.timestamp_us(), 500234);
        assert_eq!(decoded.dx(), -25);
        assert_eq!(decoded.dy(), 42);
        assert_eq!(decoded.wheel_v(), 1);
        assert_eq!(decoded.wheel_h(), -1);
        assert!(decoded.flags().is_set(ButtonFlags::BTN_LEFT));
        assert!(decoded.flags().is_set(ButtonFlags::BTN_EXTRA));
        assert!(!decoded.flags().is_set(ButtonFlags::BTN_RIGHT));
    }

    #[test]
    fn test_anti_replay_sliding_window() {
        let mut window = AntiReplayWindow::new();

        // 正常單調遞增
        assert!(window.validate_and_update(1));
        assert!(window.validate_and_update(2));
        assert!(window.validate_and_update(5));

        // 窗口內的舊封包亂序到達 (Out of Order)
        assert!(window.validate_and_update(3));
        assert!(window.validate_and_update(4));

        // 重複封包 (Replay Attack) -> Drop
        assert!(!window.validate_and_update(2));
        assert!(!window.validate_and_update(5));
        assert!(!window.validate_and_update(1));

        // 巨大跳躍 (超過 64)
        assert!(window.validate_and_update(100));

        // 檢查之前的舊序號是否已被排除在窗口外 (100 - 30 = 70 >= 64)
        assert!(!window.validate_and_update(30));
        assert!(!window.validate_and_update(35));

        // 檢查窗口邊界內封包 (100 - 90 = 10 < 64)
        assert!(window.validate_and_update(90));
        // 重放剛驗證過的 90 -> Drop
        assert!(!window.validate_and_update(90));
    }

    #[test]
    fn test_noise_ik_channel_e2e_encryption() {
        let builder_init = Builder::new(NOISE_PARAMS.parse().unwrap());
        let builder_resp = Builder::new(NOISE_PARAMS.parse().unwrap());

        // 生成靜態密鑰對
        let static_init = builder_init.generate_keypair().unwrap();
        let static_resp = builder_resp.generate_keypair().unwrap();

        // Initiator 狀態：持有 Responder 的 Static Public Key (0-RTT)
        let mut initiator = builder_init
            .local_private_key(&static_init.private)
            .remote_public_key(&static_resp.public)
            .build_initiator()
            .unwrap();

        // Responder 狀態：持有自身 Private Key
        let mut responder = builder_resp
            .local_private_key(&static_resp.private)
            .build_responder()
            .unwrap();

        // 模擬 0-RTT Handshake 流程 (Msg 1: -> e, es, s, ss)
        let mut msg1 = [0u8; 128];
        let len1 = initiator.write_message(b"", &mut msg1).unwrap();

        let mut payload_buf = [0u8; 128];
        responder.read_message(&msg1[..len1], &mut payload_buf).unwrap();

        // Msg 2: <- e, ee
        let mut msg2 = [0u8; 128];
        let len2 = responder.write_message(b"", &mut msg2).unwrap();
        initiator.read_message(&msg2[..len2], &mut payload_buf).unwrap();

        // 進入 TransportState
        let tx_transport = initiator.into_transport_mode().unwrap();
        let rx_transport = responder.into_transport_mode().unwrap();

        // 建立本地 UDP 迴圈連線測試
        let sock_tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sock_rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rx_addr = sock_rx.local_addr().unwrap();
        sock_tx.connect(rx_addr).unwrap();

        let mut channel_tx = NoiseIkUdpChannel::new(sock_tx, tx_transport);
        let mut channel_rx = NoiseIkUdpChannel::new(sock_rx, rx_transport);

        // 測試發送與接收 RelMotionPacket
        let pkt = RelMotionPacket::new(1, 123456, 12, -8, 0, 0, ButtonFlags::default());

        let t0 = Instant::now();
        channel_tx.send_rel_motion(&pkt).expect("Send success");

        let mut rx_buf = [0u8; 256];
        let received_pkt = channel_rx.recv_and_verify(&mut rx_buf).expect("Receive & Decrypt success");
        let elapsed = t0.elapsed();

        assert_eq!(received_pkt.sequence(), 1);
        assert_eq!(received_pkt.dx(), 12);
        assert_eq!(received_pkt.dy(), -8);

        // E2E 延遲驗證：本地迴路延遲應遠小於 1.5ms
        println!("E2E Local UDP Round-trip Latency: {:?}", elapsed);
        assert!(elapsed.as_micros() < 1500, "Local E2E latency must be < 1.5ms");
    }
}
