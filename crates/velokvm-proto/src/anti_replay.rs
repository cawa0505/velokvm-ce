/// Anti-Replay 滑動窗口長度 (64 Bit Window)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntiReplayWindow {
    last_seq: u64,
    window: u64,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    #[inline(always)]
    pub fn new() -> Self {
        Self { last_seq: 0, window: 0 }
    }

    /// 檢查序號合法性並更新窗口
    /// - 若序號有效且未被重複發送，更新內部狀態並回傳 true
    /// - 若為 Replay 攻擊或過舊封包，回傳 false 並丟棄
    #[inline(always)]
    pub fn validate_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            // 序號由 1 開始，0 為無效序號
            return false;
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff < 64 {
                self.window = (self.window << diff) | 1;
            } else {
                self.window = 1;
            }
            self.last_seq = seq;
            true
        } else {
            let diff = self.last_seq - seq;
            if diff >= 64 {
                return false; // 過舊封包，超過窗口長度，直接 Drop
            }
            if (self.window & (1u64 << diff)) != 0 {
                return false; // 重複（Replayed）封包，直接 Drop
            }
            self.window |= 1u64 << diff;
            true
        }
    }

    #[inline(always)]
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }
}
