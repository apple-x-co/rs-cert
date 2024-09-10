#[derive(Debug)]
pub struct Cert {
    pub version: String,
    pub serial: String,
    pub subject: String,
    pub issuer: String,
    pub validity: Validity,
}

#[derive(Debug)]
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
    pub is_valid: bool,
}

impl Cert {
    pub fn new(
        version: &str,
        serial: &str,
        subject: &str,
        issuer: &str,
        not_before: &str,
        not_after: &str,
        is_valid: bool,
    ) -> Cert {
        Cert {
            version: version.to_string(),
            serial: serial.to_string(),
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            validity: Validity {
                not_before: not_before.to_string(),
                not_after: not_after.to_string(),
                is_valid,
            },
        }
    }
}