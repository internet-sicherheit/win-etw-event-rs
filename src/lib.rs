#![doc = include_str!("../README.md")]

pub mod modern_event;

pub use guid::*;

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

mod guid {
    /// Global Unique Identifier (GUID)
    ///
    /// A text string representing a Class identifier (ID).
    /// The valid format for a GUID is `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` where X is a hex digit (0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F).
    ///
    /// # Examples
    /// GUIDs can be constructed from strings as well as 128-bit unsigned integers.
    /// ```
    /// # use win_etw_event::Guid;
    /// # use std::str::FromStr;
    /// // Building from a u128
    /// let class_id: Guid = 0x6B29FC40_CA47_1067_B31D_00DD010662DA.into();
    /// // Building from a str
    /// let class_id: Guid = "{6B29FC40-CA47-1067-B31D-00DD010662DA}".parse().unwrap();
    /// ```
    ///
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

    impl From<Guid> for u128 {
        fn from(value: Guid) -> Self {
            value.0
        }
    }

    impl std::str::FromStr for Guid {
        type Err = ParseGuidError;

        /// Parse GUIDs in the form of `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` where _X_ is a hex digit
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let stripped = s
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
                .ok_or(ParseGuidError)?;

            let mut hex = stripped.to_string();
            hex.retain(|c| c != '-');

            let value = u128::from_str_radix(&hex, 16).map_err(|_| ParseGuidError)?;

            Ok(Guid(value))
        }
    }

    impl std::fmt::Display for Guid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
            //        0x00000000_0000_0000_0000_000000000000
            let d1 = self.0 & 0x00000000_0000_0000_0000_FFFFFFFFFFFF;
            let d2 = (self.0 & 0x00000000_0000_0000_FFFF_000000000000) >> (12 * 4);
            let d3 = (self.0 & 0x00000000_0000_FFFF_0000_000000000000) >> (16 * 4);
            let d4 = (self.0 & 0x00000000_FFFF_0000_0000_000000000000) >> (20 * 4);
            let d5 = (self.0 & 0xFFFFFFFF_0000_0000_0000_000000000000) >> (24 * 4);
            write!(
                f,
                "{{{:08X}-{:04X}-{:04X}-{:04X}-{:012X}}}",
                d5, d4, d3, d2, d1
            )
        }
    }
    impl std::fmt::Debug for Guid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "GUID {{ {:032X} }}", self.0)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn test_parse() {
            let value: u128 = 0x6B29FC40_CA47_1067_B31D_00DD010662DA;
            assert_eq!(
                Guid::from_str("{6B29FC40-CA47-1067-B31D-00DD010662DA}").unwrap(),
                value.into()
            );
            assert_eq!(
                Guid::from_str("{6b29fc40-ca47-1067-b31d-00dd010662da}").unwrap(),
                value.into()
            );
        }

        #[test]
        fn test_display() {
            let value: Guid = 0x6B29FC40_CA47_1067_B31D_00DD010662DA.into();
            let guid_string = value.to_string();
            assert_eq!(&guid_string, "{6B29FC40-CA47-1067-B31D-00DD010662DA}");
        }

        #[test]
        fn test_debug() {
            use std::fmt::Write;
            let mut debug_string = String::new();
            write!(
                debug_string,
                "{:?}",
                Guid::from_str("{6b29fc40-ca47-1067-b31d-00dd010662da}").unwrap()
            )
            .unwrap();

            assert_eq!(&debug_string, "GUID { 6B29FC40CA471067B31D00DD010662DA }")
        }
    }
}
