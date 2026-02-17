#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No wrapping found for key {0} and parent {1}")]
    InvalidWrapping(String, String),
    #[error("Key {0} not found")]
    InvalidKeyID(String),
    #[error("Parent key ID is not in graph")]
    InvalidParentKeyID(String),
    #[error("Key graph error: {0}")]
    NoSuchPath(String),
    #[error("Generic error: {0}")]
    Generic(String),

    // Dependencies
    #[error("Crypto error")]
    Crypto(#[from] aead::Error),
    #[cfg(feature = "json")]
    #[error("JSON (de)serialization error")]
    JSON(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[cfg(feature = "aes256-gcm")]
    #[error("Invalid key size")]
    InvalidKeySize(#[from] aes_gcm::aes::cipher::InvalidLength),
    // Add more...
}

pub type Result<T> = std::result::Result<T, Error>;
