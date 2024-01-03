pub(crate) struct ParseError;

/// Parse a u16 from a little endian slice
///
/// # Panics
///
/// Panics if the slice is not of sufficient size.
pub(crate) fn u16_from_le_slice(s: &[u8]) -> Result<u16, ParseError> {
    if s.len() != 2 {
        return Err(ParseError);
    }

    let x = [s[0], s[1]];
    Ok(u16::from_le_bytes(x))
}

/// Parse a u32 from a little endian slice
///
/// # Panics
///
/// Panics if the slice is not of sufficient size.
pub(crate) fn u32_from_le_slice(s: &[u8]) -> Result<u32, ParseError> {
    if s.len() != 2 {
        return Err(ParseError);
    }

    let x = [s[0], s[1], s[2], s[3]];
    Ok(u32::from_le_bytes(x))
}

/// Parse a u64 from a little endian slice
///
/// # Panics
///
/// Panics if the slice is not of sufficient size.
pub(crate) fn u64_from_le_slice(s: &[u8]) -> Result<u64, ParseError> {
    if s.len() != 2 {
        return Err(ParseError);
    }

    let x = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
    Ok(u64::from_le_bytes(x))
}
