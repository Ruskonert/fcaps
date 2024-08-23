use std::ops::{BitAnd, BitOr, BitXor, Not};

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum IPProtocol {
    NONE = 0,
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl Into<u8> for IPProtocol {
    fn into(self) -> u8 {
        self as u8
    }
}

impl Into<u16> for IPProtocol {
    fn into(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum TcpOption {
    EndOfOptionList,                          // 0x00
    NoOperation,                              // 0x01
    MaximumSegmentSize(u16),                  // 0x02
    WindowScale(u8),                          // 0x03
    SelectiveAcknowledgment(Vec<(u32, u32)>), // 0x04
    SACKPermitted,       // 0x05 (Assumed as a placeholder, adjust if different)
    Timestamp(u32, u32), // 0x08
    Unknown,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum TcpFlag {
    Fin = 0b00000001,
    Syn = 0b00000010,
    Reset = 0b00000100,
    Push = 0b00001000,
    Ack = 0b00010000,
    Urgent = 0b00100000,
    Ecn = 0b01000000,
    Congest = 0b10000000,
}

impl BitOr for TcpFlag {
    type Output = u8;

    fn bitor(self, rhs: Self) -> Self::Output {
        (self as u8) | (rhs as u8)
    }
}

impl BitAnd for TcpFlag {
    type Output = u8;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self as u8) & (rhs as u8)
    }
}

impl BitXor for TcpFlag {
    type Output = u8;

    fn bitxor(self, rhs: Self) -> Self::Output {
        (self as u8) ^ (rhs as u8)
    }
}

impl Not for TcpFlag {
    type Output = u8;

    fn not(self) -> Self::Output {
        !(self as u8)
    }
}

impl Into<u8> for TcpFlag {
    fn into(self) -> u8 {
        self as u8
    }
}

impl Into<u16> for TcpFlag {
    fn into(self) -> u16 {
        self as u16
    }
}

impl TcpFlag {
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0b00000001 => Some(TcpFlag::Fin),
            0b00000010 => Some(TcpFlag::Syn),
            0b00000100 => Some(TcpFlag::Reset),
            0b00001000 => Some(TcpFlag::Push),
            0b00010000 => Some(TcpFlag::Ack),
            0b00100000 => Some(TcpFlag::Urgent),
            0b01000000 => Some(TcpFlag::Ecn),
            0b10000000 => Some(TcpFlag::Congest),
            _ => None,
        }
    }
}

impl TcpOption {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            TcpOption::EndOfOptionList => vec![0x00],
            TcpOption::NoOperation => vec![0x01],
            TcpOption::MaximumSegmentSize(mss) => {
                let mss_bytes = mss.to_be_bytes();
                vec![0x02, 0x04] // Kind + Length
                    .into_iter()
                    .chain(mss_bytes.iter().cloned())
                    .collect()
            }
            TcpOption::WindowScale(scale) => vec![0x03, 0x03, *scale],
            TcpOption::SelectiveAcknowledgment(blocks) => {
                let mut bytes = vec![0x04, 0x02 + 8 * blocks.len() as u8];
                for &(start, end) in blocks {
                    bytes.extend_from_slice(&start.to_be_bytes());
                    bytes.extend_from_slice(&end.to_be_bytes());
                }
                bytes
            }
            TcpOption::Timestamp(ts_value, ts_echo) => {
                let mut bytes = vec![0x08, 0x0A];
                bytes.extend_from_slice(&ts_value.to_be_bytes());
                bytes.extend_from_slice(&ts_echo.to_be_bytes());
                bytes
            }
            TcpOption::SACKPermitted => vec![0x05, 0x02], // SACK Permitted
            TcpOption::Unknown => vec![],
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Layer {
    L1,
    L2,
    L3,
    L4,
    L5,
    L6,
    L7,
}

impl Default for Layer {
    fn default() -> Self {
        Self::L1
    }
}

impl Default for IPProtocol {
    fn default() -> Self {
        Self::NONE
    }
}
