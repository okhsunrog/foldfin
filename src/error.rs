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
