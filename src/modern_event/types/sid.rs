use std::fmt::Display;

/// Security Identifier
///
/// A identifier used to uniquely identify a security principal or security group.
/// For further information refer to the [Microsoft Windows Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    revision: u8,
    identifier_authority: [u8; 6],
    sub_auhtoritys: Vec<u32>,
}
impl Sid {
    pub fn parse<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let mut header = [0_u8; 2];
        let mut ident_auth = [0_u8; 6];
        r.read_exact(&mut header)?;
        r.read_exact(&mut ident_auth)?;

        let mut sub_auths = Vec::with_capacity(header[1] as usize);

        for _ in 0..header[1] {
            let mut buf = [0_u8; 4];
            r.read_exact(&mut buf)?;
            sub_auths.push(u32::from_le_bytes(buf));
        }
        Ok(Sid {
            revision: header[0],
            identifier_authority: ident_auth,
            sub_auhtoritys: sub_auths,
        })
    }
}

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ident_auth_bytes = [0_u8; 8];
        ident_auth_bytes
            .iter_mut()
            .skip(2)
            .zip(self.identifier_authority.iter())
            .for_each(|(a, b)| *a = *b);

        let ident_auth = format!("{}", u64::from_be_bytes(ident_auth_bytes));

        let mut sub_auths = String::new();
        use std::fmt::Write;
        for x in &self.sub_auhtoritys {
            write!(sub_auths, "-{x}")?;
        }

        write!(f, "s-{}-{}{}", self.revision, ident_auth, sub_auths)
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use super::Sid;

    #[test]
    fn test_display() {
        let sid = Sid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_auhtoritys: vec![632, 723811915, 3361004348, 33368],
        };

        let sid_string = sid.to_string();

        assert_eq!(sid_string, "s-1-5-632-723811915-3361004348-33368");
    }

    #[test]
    fn test_parse() {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(1); // revision 1
        buf.push(4); // sub authority count 4
        [0_u8, 0, 0, 0, 0, 5].iter().for_each(|i| buf.push(*i)); // ident authority 5
        632_u32.to_le_bytes().iter().for_each(|i| buf.push(*i));
        723811915_u32
            .to_le_bytes()
            .iter()
            .for_each(|i| buf.push(*i));
        3361004348_u32
            .to_le_bytes()
            .iter()
            .for_each(|i| buf.push(*i));
        33368_u32.to_le_bytes().iter().for_each(|i| buf.push(*i));

        let buf_len = buf.len();

        let mut buf = Cursor::new(buf);
        let sid = Sid::parse(&mut buf).expect("Failed to parse sid from buffer!");

        let expected = Sid {
            revision: 1,
            identifier_authority: [0, 0, 0, 0, 0, 5],
            sub_auhtoritys: vec![632, 723811915, 3361004348, 33368],
        };

        assert_eq!(sid, expected);
        assert_eq!(buf.position(), buf_len as u64);
    }
}
