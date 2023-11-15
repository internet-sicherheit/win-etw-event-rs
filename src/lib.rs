#![doc = include_str!("../README.md")]
use std::str::FromStr;

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

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Guid(u128);
#[derive(Debug, PartialEq, Eq)]
pub struct ParseGuidError;

impl From<u128> for Guid {
    fn from(value: u128) -> Self {
        Guid(value)
    }
}
impl FromStr for Guid {
    type Err = ParseGuidError;

    /// Parse GUIDs in the form of `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` where _X_ is a hex digit
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or(ParseGuidError)?;

        let hex = stripped.replace('-', "_");

        let value = u128::from_str_radix(&hex, 16).map_err(|_| ParseGuidError)?;

        Ok(Guid(value))
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        //        0x00000000_0000_0000_0000_000000000000
        let d1 = self.0 & 0x00000000_0000_0000_0000_FFFFFFFFFFFF;
        let d2 = self.0 & 0x00000000_0000_0000_FFFF_000000000000;
        let d3 = self.0 & 0x00000000_0000_FFFF_0000_000000000000;
        let d4 = self.0 & 0x00000000_FFFF_0000_0000_000000000000;
        let d5 = self.0 & 0xFFFFFFFF_0000_0000_0000_000000000000;
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
            d5, d4, d3, d2, d1
        )
    }
}
impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GUID {{{:032X}}}", self.0)
    }
}
