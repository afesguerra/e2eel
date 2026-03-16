use crate::{Key, Result};

#[cfg(any(feature = "aes256-gcm", feature = "xsalsa20-poly1305"))]
pub mod aead;

/// Trait for encryption/decryption implementations.
/// `N` is the size of the key in bytes, `M` is the size of an encrypted key in bytes.
/// e.g. `impl CryptoProvider<32, 60> for MyProvider`.
pub trait CryptoProvider<const N: usize, const M: usize>: Send + Sync {
    /// Encrypt `plaintext` key material using `key`
    fn encrypt(&self, key: &Key<N>, plaintext: &Key<N>) -> Result<[u8; M]>;
    /// Decrypt ciphertext back into key material using `key`
    fn decrypt(&self, key: &Key<N>, ciphertext: &[u8; M]) -> Result<Key<N>>;
    /// Generate a new random key
    fn generate_key(&self) -> Result<Key<N>>;
}
