//! Errors callers can classify without parsing log messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP/2: {0}")]
    H2(#[from] h2::Error),
    #[error("TLS: {0}")]
    Tls(#[source] anyhow::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] anyhow::Error),
    #[error("request rejected (HTTP {0})")]
    Rejected(u16),
    #[error("timed out during {0}")]
    Timeout(&'static str),
    #[error("carrier closed")]
    Closed,
    #[error("path payload capacity {available} is below required MTU {required}")]
    PathMtu { required: usize, available: usize },
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Conservative candidate fallback: certificate, authentication, policy and
    /// unclassified protocol failures never trigger another transport.
    pub fn permits_transport_fallback(&self) -> bool {
        match self {
            Self::Timeout(_) | Self::PathMtu { .. } | Self::Closed => true,
            Self::Rejected(501) => true,
            Self::Unsupported("QUIC datagrams") => true,
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::TimedOut
            ),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_never_masks_identity_authorization_or_protocol_failure() {
        for error in [
            Error::Tls(anyhow::anyhow!("untrusted certificate")),
            Error::Rejected(401),
            Error::Rejected(403),
            Error::Rejected(409),
            Error::Unsupported("invalid capsule negotiation"),
            Error::Protocol(anyhow::anyhow!("malformed frame")),
        ] {
            assert!(!error.permits_transport_fallback(), "{error}");
        }
        for error in [
            Error::Timeout("QUIC handshake"),
            Error::Rejected(501),
            Error::PathMtu {
                required: 1280,
                available: 1200,
            },
            Error::Io(std::io::ErrorKind::ConnectionRefused.into()),
        ] {
            assert!(error.permits_transport_fallback(), "{error}");
        }
    }
}
