use core::mem::size_of;

/// 封包類型標籤 (1 Byte)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTag {
    Ping = 0x01,
    Pong = 0x02,
    RelMotion = 0x10,
    AbsMotion = 0x11,
    KeyAction = 0x20,
    BatchBundle = 0x30,
}

impl TryFrom<u8> for PacketTag {
    type Error = &'static str;

    #[inline(always)]
    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(PacketTag::Ping),
            0x02 => Ok(PacketTag::Pong),
            0x10 => Ok(PacketTag::RelMotion),
            0x11 => Ok(PacketTag::AbsMotion),
            0x20 => Ok(PacketTag::KeyAction),
            0x30 => Ok(PacketTag::BatchBundle),
            _ => Err("Unknown PacketTag"),
        }
    }
}

/// 8-bit 按鍵與滑鼠按鈕狀態遮罩
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ButtonFlags(pub u8);

impl ButtonFlags {
    pub const BTN_LEFT: u8   = 1 << 0;
    pub const BTN_RIGHT: u8  = 1 << 1;
    pub const BTN_MIDDLE: u8 = 1 << 2;
    pub const BTN_SIDE: u8   = 1 << 3;
    pub const BTN_EXTRA: u8  = 1 << 4;

    #[inline(always)]
    pub fn is_set(&self, bit: u8) -> bool {
        (self.0 & bit) != 0
    }

    #[inline(always)]
    pub fn set(&mut self, bit: u8) {
        self.0 |= bit;
    }

    #[inline(always)]
    pub fn clear(&mut self, bit: u8) {
        self.0 &= !bit;
    }
}

/// 微秒級 1000Hz EV_REL 相對位移 Fast-Path 封包 (共 16 Bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelMotionPacket {
    pub tag: PacketTag,          // 1 Byte: 0x10
    pub flags: ButtonFlags,      // 1 Byte: 按鈕狀態遮罩
    pub sequence: u32,           // 4 Bytes: Anti-Replay 遞增序號
    pub timestamp_us: u32,       // 4 Bytes: 微秒時間戳 (取模 2^32)
    pub dx: i16,                 // 2 Bytes: X 軸相對位移
    pub dy: i16,                 // 2 Bytes: Y 軸相對位移
    pub wheel_v: i8,             // 1 Byte: 垂直滾輪位移
    pub wheel_h: i8,             // 1 Byte: 水平滾輪位移
}

pub const REL_MOTION_SIZE: usize = size_of::<RelMotionPacket>();

// 編譯期確保結構體大小完全等於 16 Bytes
const _: [(); 16] = [(); REL_MOTION_SIZE];

impl RelMotionPacket {
    #[inline(always)]
    pub fn new(sequence: u32, timestamp_us: u32, dx: i16, dy: i16, wheel_v: i8, wheel_h: i8, flags: ButtonFlags) -> Self {
        Self {
            tag: PacketTag::RelMotion,
            flags,
            sequence,
            timestamp_us,
            dx,
            dy,
            wheel_v,
            wheel_h,
        }
    }

    /// 從 byte slice 進行零拷貝轉換 (Zero-Allocation)
    ///
    /// `#[repr(C, packed)]` 結構之對齊要求為 1，故任意長度 ≥ 16 且 Tag 合法的 slice
    /// 均可安全指向；但因其欄位可能不對齊， Getter 存取多位元組欄位時
    /// 必須使用 `read_unaligned` 複製值而非借用 reference。
    #[inline(always)]
    pub fn from_bytes(slice: &[u8]) -> Option<&Self> {
        if slice.len() < REL_MOTION_SIZE {
            return None;
        }
        if slice[0] != PacketTag::RelMotion as u8 {
            return None;
        }
        // 指標轉換：對齊為 1，任意 valid slice 均可安全指向
        unsafe { Some(&*(slice.as_ptr() as *const RelMotionPacket)) }
    }

    /// 轉出為二進位 byte slice (Zero-Allocation)
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                REL_MOTION_SIZE,
            )
        }
    }

    // Unaligned-Safe Getter 方法（複製值而非借用 reference）
    // ponytail: repr(C, packed) 欄位可能未對齊，讀取時複製值而非借用，避免 UB
    #[inline(always)]
    pub fn sequence(&self) -> u32 {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.sequence)) }
    }

    #[inline(always)]
    pub fn timestamp_us(&self) -> u32 {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.timestamp_us)) }
    }

    #[inline(always)]
    pub fn dx(&self) -> i16 {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.dx)) }
    }

    #[inline(always)]
    pub fn dy(&self) -> i16 {
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!(self.dy)) }
    }

    #[inline(always)]
    pub fn wheel_v(&self) -> i8 {
        self.wheel_v
    }

    #[inline(always)]
    pub fn wheel_h(&self) -> i8 {
        self.wheel_h
    }

    #[inline(always)]
    pub fn flags(&self) -> ButtonFlags {
        self.flags
    }
}
