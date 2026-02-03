use thiserror::Error;

/// Library error types for CoReVo operations
#[derive(Error, Debug)]
pub enum CorevoError {
    #[error("Chain connection failed: {0}")]
    ChainConnection(String),

    #[error("Transaction failed: {0}")]
    Transaction(String),

    #[error("Invalid secret URI: {0}")]
    InvalidSecretUri(String),

    #[error("Account not found on chain: {0}")]
    AccountNotFound(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("MongoDB error: {0}")]
    Database(#[from] mongodb::error::Error),

    #[error("Codec decode error: {0}")]
    Decode(String),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid configuration: {0}")]
    Config(String),

    #[error("Subxt error: {0}")]
    Subxt(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<subxt::Error> for CorevoError {
    fn from(err: subxt::Error) -> Self {
        CorevoError::Subxt(err.to_string())
    }
}

impl From<subxt_signer::sr25519::Error> for CorevoError {
    fn from(err: subxt_signer::sr25519::Error) -> Self {
        CorevoError::InvalidSecretUri(err.to_string())
    }
}

impl From<subxt_signer::SecretUriError> for CorevoError {
    fn from(err: subxt_signer::SecretUriError) -> Self {
        CorevoError::InvalidSecretUri(err.to_string())
    }
}

impl From<crypto_box::aead::Error> for CorevoError {
    fn from(_: crypto_box::aead::Error) -> Self {
        CorevoError::Encryption("AEAD operation failed".to_string())
    }
}

impl From<codec::Error> for CorevoError {
    fn from(err: codec::Error) -> Self {
        CorevoError::Decode(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CorevoError>;
