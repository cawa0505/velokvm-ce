use crate::anti_replay::AntiReplayWindow;
use crate::protocol::{RelMotionPacket, REL_MOTION_SIZE};
use snow::TransportState;
use std::net::UdpSocket;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Noise cryptographic error: {0}")]
    Noise(#[from] snow::Error),
    #[error("Invalid packet layout or tag")]
    InvalidPacket,
    #[error("Anti-replay check failed: sequence {0} replayed or too old")]
    ReplayDetected(u32),
}

/// 0-RTT Noise_IK 加密 UDP 傳輸通道
pub struct NoiseIkUdpChannel {
    socket: UdpSocket,
    transport: TransportState,
    anti_replay: AntiReplayWindow,
}

impl NoiseIkUdpChannel {
    pub fn new(socket: UdpSocket, transport: TransportState) -> Self {
        Self {
            socket,
            transport,
            anti_replay: AntiReplayWindow::new(),
        }
    }

    /// 發送微秒級加密相對位移封包 (Zero-Heap Allocation 發送路徑)
    #[inline(always)]
    pub fn send_rel_motion(&mut self, pkt: &RelMotionPacket) -> Result<usize, ChannelError> {
        let raw_bytes = pkt.as_bytes();
        let mut cipher_buf = [0u8; REL_MOTION_SIZE + 16]; // ChaCha20-Poly1305 MAC 佔 16 Bytes
        
        let len = self.transport.write_message(raw_bytes, &mut cipher_buf)?;
        self.socket.send(&cipher_buf[..len])?;
        Ok(len)
    }

    /// 接收並驗證加密 UDP 封包
    #[inline(always)]
    pub fn recv_and_verify(&mut self, buf: &mut [u8]) -> Result<RelMotionPacket, ChannelError> {
        let (amt, _) = self.socket.recv_from(buf)?;
        let mut plaintext = [0u8; 128]; // 足以容納 Fast-path 封包

        let len = self.transport.read_message(&buf[..amt], &mut plaintext)?;
        
        let pkt = RelMotionPacket::from_bytes(&plaintext[..len])
            .ok_or(ChannelError::InvalidPacket)?;

        let seq = pkt.sequence();
        if !self.anti_replay.validate_and_update(seq as u64) {
            return Err(ChannelError::ReplayDetected(seq));
        }

        Ok(*pkt)
    }

    pub fn anti_replay_mut(&mut self) -> &mut AntiReplayWindow {
        &mut self.anti_replay
    }
}
