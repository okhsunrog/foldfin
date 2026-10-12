//! Credentials are supplied by the embedding application, never read from its environment.
#[derive(Clone)]
pub struct Credential(String);

impl Credential {
    pub fn bearer(token: impl Into<String>) -> crate::error::Result<Self> {
        let token = token.into();
        if token.len() < 32 || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(crate::error::Error::InvalidConfig(
                "bearer token must contain at least 32 ASCII letters/digits".into(),
            ));
        }
        Ok(Self(format!("Bearer {token}")))
    }

    pub(crate) fn header(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}
