use std::fmt::Display;

#[derive(Debug, Clone)]
struct Sid {
    revision: u8,
    identifier_authority: [u8; 6],
    sub_auhtority: Vec<u32>,
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
        for x in &self.sub_auhtority {
            write!(sub_auths, "-{x}")?;
        }

        write!(f, "s-{}-{}-{}", self.revision, ident_auth, sub_auths)
    }
}

#[cfg(test)]
mod test {
    use super::Sid;

    fn _test_display() {
        let sid = Sid {
            revision: todo!(),
            identifier_authority: todo!(),
            sub_auhtority: todo!(),
        };
    }
}
