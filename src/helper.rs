use std::io::{self, Seek};

use byteorder::{BigEndian, ByteOrder};

#[derive(Clone, Copy, Debug)]
pub(crate) struct ParseError;

/// Parse a u16 from a little endian slice
///
/// # Errors
///
/// Errors if the slice is not of sufficient size.
pub(crate) fn u16_from_le_slice(s: &[u8]) -> Result<u16, ParseError> {
    if s.len() != 2 {
        return Err(ParseError);
    }

    let x = [s[0], s[1]];
    Ok(u16::from_le_bytes(x))
}

/// Parse a u32 from a little endian slice
///
/// # Errors
///
/// Errors if the slice is not of sufficient size.
pub(crate) fn u32_from_le_slice(s: &[u8]) -> Result<u32, ParseError> {
    if s.len() != 4 {
        return Err(ParseError);
    }

    let x = [s[0], s[1], s[2], s[3]];
    Ok(u32::from_le_bytes(x))
}

/// Parse a u64 from a little endian slice
///
/// # Errors
///
/// Errors if the slice is not of sufficient size.
pub(crate) fn u64_from_le_slice(s: &[u8]) -> Result<u64, ParseError> {
    if s.len() != 8 {
        return Err(ParseError);
    }

    let x = [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]];
    Ok(u64::from_le_bytes(x))
}

pub(crate) fn read_utf16_string<T: AsRef<[u8]>>(r: &mut io::Cursor<T>) -> io::Result<String> {
    // parsing a utf16 string from a u8 buffer isnt't simple...
    let reference = r.get_ref().as_ref();
    let start = r.position();
    let s = &reference[start as usize..];

    // We get us a &[u8] which contains all remaining bytes and truncate it to a even number of bytes
    let s = if s.len() % 2 != 0 {
        &s[..s.len() - 1]
    } else {
        s
    };

    // Now we can create a [u16] slice to find the utf16 zero terminated string
    let mut u16_buf = vec![0; s.len() / 2];
    BigEndian::read_u16_into(s, &mut u16_buf);
    let u16cstr = widestring::U16CStr::from_slice_truncate(&u16_buf)
        .map_err(|_| io::Error::other("Missing nul terminator for unicode string!"))?;

    let size = u16cstr.len(); // number of elements not including termination
    r.seek(std::io::SeekFrom::Current((size * 2 + 2) as i64))?;

    Ok(u16cstr.to_string_lossy())
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_utf16_from_buf() {
        use std::io;
        use std::io::Read;
        /// A buffer with "notepad.exe" as utf16 preceeded by 3x 0xAA and followed by 3x 0xBB
        ///
        /// By having three extra bytes at the end we test that strings are read correctly from uneven remaining bytes.
        const CONTAINS_UTF16_C_STRING: &[u8] = &[
            0xAA, 0xAA, 0xAA, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x74, 0x00, 0x65, 0x00, 0x70, 0x00,
            0x61, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x00, 0xBB,
            0xBB, 0xBB,
        ];

        let mut cur = io::Cursor::new(CONTAINS_UTF16_C_STRING);

        cur.set_position(3);

        let s = super::read_utf16_string(&mut cur).unwrap();
        assert_eq!(s, "notepad.exe");

        let mut buf = Vec::new();
        cur.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf, &[0xBB, 0xBB, 0xBB]);
    }
}
