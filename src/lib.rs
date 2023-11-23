#![doc = include_str!("../README.md")]

pub mod modern_event;

/// Trace Header formats
///
/// Events can be one of six different formats,
/// each having a 32-bit and a 64-bit version.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum TraceHeaderType {
    System32 = 0x01,
    System64 = 0x02,
    Compact32 = 0x03,
    Compact64 = 0x04,
    Perfinfo32 = 0x10,
    Perfinfo64 = 0x11,
    ModernEvent32 = 0x12,
    ModernEvent64 = 0x13,
    Full32 = 0x0A,
    Full64 = 0x14,
    Instance32 = 0x0B,
    Instance64 = 0x15,
}
