use scrypt::{errors::InvalidOutputLen, password_hash::rand_core};

/// Error kind for minisign-rs
#[derive(Debug, Clone)]
pub enum ErrorKind {
    Io,
    Kdf,
    PrehashedMismatch,
    PublicKey,
    SecretKey,
    SignatureError,
}
impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Io => write!(f, "io error"),
            ErrorKind::Kdf => write!(f, "kdf error"),
            ErrorKind::PrehashedMismatch => write!(f, "prehashed mismatch"),
            ErrorKind::PublicKey => write!(f, "public key error"),
            ErrorKind::SecretKey => write!(f, "secret key error"),
            ErrorKind::SignatureError => write!(f, "signature error"),
        }
    }
}
/// Error type for minisign-rs
///
/// This type is used for all errors in minisign-rs
#[derive(Debug)]
pub struct SError {
    kind: ErrorKind,
    error: Box<dyn std::error::Error + Send + Sync>,
}
impl std::error::Error for SError {}
impl std::fmt::Display for SError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kind:{} error:{}", self.kind, self.error)
    }
}
impl SError {
    pub(crate) fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            error: error.into(),
        }
    }
}
impl From<rand_core::Error> for SError {
    fn from(error: rand_core::Error) -> Self {
        Self {
            kind: ErrorKind::Kdf,
            error: Box::new(error),
        }
    }
}
impl From<std::io::Error> for SError {
    fn from(error: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            error: Box::new(error),
        }
    }
}
impl From<ed25519_dalek::SignatureError> for SError {
    fn from(error: ed25519_dalek::SignatureError) -> Self {
        Self {
            kind: ErrorKind::SignatureError,
            error: Box::new(error),
        }
    }
}
impl From<scrypt::errors::InvalidParams> for SError {
    fn from(err: scrypt::errors::InvalidParams) -> SError {
        SError::new(ErrorKind::Kdf, err.to_string())
    }
}
impl From<scrypt::errors::InvalidOutputLen> for SError {
    fn from(err: InvalidOutputLen) -> SError {
        SError::new(ErrorKind::Kdf, err.to_string())
    }
}
pub type Result<T> = std::result::Result<T, SError>;
