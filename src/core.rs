use aes_gcm::aes::cipher::InvalidLength;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptorError {
    #[error("No wrapping found for key {0} and parent {1}")]
    InvalidWrapping(String, String),
    #[error("Key {0} not found")]
    InvalidKeyID(String),
    #[error("Parent key ID is not in graph")]
    InvalidParentKeyID(String),
    #[error("Key graph error: {0}")]
    NoSuchPath(String),

    // Dependencies
    #[error("Crypto error")]
    Crypto(#[from] aes_gcm::Error),
    #[error("JSON (de)serialization error")]
    JSON(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[error("Invalid key size")]
    InvalidKeySize(#[from] InvalidLength),
    // Add more...
}

pub type Result<T> = std::result::Result<T, EncryptorError>;
