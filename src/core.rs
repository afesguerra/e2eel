use std::fmt;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-size buffer of sensitive key material that is automatically
/// zeroed in memory when dropped.
///
/// Prefer this type over raw arrays whenever handling plaintext key bytes.
/// The inner bytes are never exposed through `Debug` or `Display`.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq)]
pub struct Key<const N: usize>([u8; N]);

impl<const N: usize> From<[u8; N]> for Key<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> Deref for Key<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for Key<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key<{N}>([REDACTED])")
    }
}

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
    /// Corrupted graph, probably a bug or data corruption
    #[error("Corrupted graph")]
    CorruptedGraph,
    #[error("Generic error: {0}")]
    Generic(String),

    // Dependencies
    #[cfg(any(feature = "aes256-gcm", feature = "xsalsa20-poly1305"))]
    #[error("Crypto error")]
    Crypto(#[from] aead::Error),
    #[cfg(feature = "in-memory")]
    #[error("JSON (de)serialization error")]
    JSON(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[cfg(feature = "aes256-gcm")]
    #[error("Invalid key size")]
    InvalidKeySize(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("Key ID {0} already exists in graph")]
    DuplicateKeyID(String),
    // Add more...
}

pub type Result<T> = std::result::Result<T, Error>;
