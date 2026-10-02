use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommonError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("PoW solving timed out")]
    PowTimeout,
    #[error("Invalid Proof-of-Work challenge")]
    InvalidPowChallenge,
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Authentication failure")]
    Unauthorized,
    #[error("Resource not found: {0}")]
    NotFound(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type CommonResult<T> = Result<T, CommonError>;
