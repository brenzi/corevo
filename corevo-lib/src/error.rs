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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_chain_connection() {
        let err = CorevoError::ChainConnection("connection refused".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Chain connection failed"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn test_error_display_transaction() {
        let err = CorevoError::Transaction("nonce too low".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Transaction failed"));
        assert!(display.contains("nonce too low"));
    }

    #[test]
    fn test_error_display_invalid_secret_uri() {
        let err = CorevoError::InvalidSecretUri("bad phrase".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Invalid secret URI"));
    }

    #[test]
    fn test_error_display_account_not_found() {
        let err = CorevoError::AccountNotFound("5GrwvaEF...".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Account not found"));
    }

    #[test]
    fn test_error_display_encryption() {
        let err = CorevoError::Encryption("key mismatch".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Encryption failed"));
    }

    #[test]
    fn test_error_display_decryption() {
        let err = CorevoError::Decryption("invalid ciphertext".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Decryption failed"));
    }

    #[test]
    fn test_error_display_decode() {
        let err = CorevoError::Decode("unexpected byte".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Codec decode error"));
    }

    #[test]
    fn test_error_display_config() {
        let err = CorevoError::Config("missing field".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Invalid configuration"));
    }

    #[test]
    fn test_error_display_subxt() {
        let err = CorevoError::Subxt("RPC error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Subxt error"));
    }

    #[test]
    fn test_error_from_hex_decode() {
        let hex_err = hex::decode("not hex").unwrap_err();
        let err: CorevoError = hex_err.into();
        let display = format!("{}", err);
        assert!(display.contains("Hex decode error"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: CorevoError = io_err.into();
        let display = format!("{}", err);
        assert!(display.contains("IO error"));
    }

    #[test]
    fn test_error_debug_impl() {
        let err = CorevoError::ChainConnection("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("ChainConnection"));
    }
}
