use std::marker::PhantomData;

use super::CryptoProvider;
use crate::{Error, Key, Result};
use aead::generic_array::typenum::Unsigned;
use aead::{Aead, AeadCore, KeyInit, OsRng};

/// Helper trait for AEAD-backed providers.
///
/// Implement this trait by specifying:
/// - `Cipher`: the AEAD cipher type
///
/// Then you automatically get a `CryptoProvider` implementation via the blanket impl below.
pub trait AeadCryptoProvider<const N: usize, const M: usize>: Send + Sync {
    type Cipher: Aead + KeyInit + Send + Sync;

    fn encrypt_aead(&self, key: &Key<N>, plaintext: &Key<N>) -> Result<[u8; M]> {
        let cipher = Self::Cipher::new_from_slice(&**key)
            .map_err(|_| Error::Generic("Key has incorrect length for cipher".to_string()))?;
        let nonce = Self::Cipher::generate_nonce(OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;


        let nonce_length = <Self::Cipher as AeadCore>::NonceSize::USIZE;
        let expected_ciphertext_len = M
            .checked_sub(nonce_length)
            .ok_or_else(|| Error::Generic("Encrypted buffer size is too small".to_string()))?;

        if ciphertext.len() != expected_ciphertext_len {
            return Err(Error::Generic(format!(
                "Ciphertext has incorrect length: expected {expected_ciphertext_len}, got {}",
                ciphertext.len()
            )));
        }

        let mut result = [0u8; M];
        result[..nonce_length].copy_from_slice(&nonce);
        result[nonce_length..].copy_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_aead(&self, key: &Key<N>, ciphertext: &[u8; M]) -> Result<Key<N>> {
        let nonce_length = <Self::Cipher as AeadCore>::NonceSize::USIZE;
        let (nonce, encrypted) = ciphertext.split_at(nonce_length);

        let cipher = Self::Cipher::new_from_slice(&**key)
            .map_err(|_| Error::Generic("Key has incorrect length for cipher".to_string()))?;

        let plaintext = cipher.decrypt(nonce.into(), encrypted)?;
        let plaintext: [u8; N] = plaintext.try_into().map_err(|_| {
            Error::Generic(format!(
                "Decrypted data has incorrect length: expected {N} bytes"
            ))
        })?;

        Ok(Key::from(plaintext))
    }

    fn generate_key_aead(&self) -> Result<Key<N>> {
        let key = Self::Cipher::generate_key(OsRng);
        let key: [u8; N] = key.as_slice().try_into().map_err(|_| {
            Error::Generic(format!(
                "Generated key has incorrect length: expected {N} bytes"
            ))
        })?;
        Ok(Key::from(key))
    }
}

impl<T, const N: usize, const M: usize> CryptoProvider<N, M> for T
where
    T: AeadCryptoProvider<N, M>,
{
    fn encrypt(&self, key: &Key<N>, plaintext: &Key<N>) -> Result<[u8; M]> {
        self.encrypt_aead(key, plaintext)
    }

    fn decrypt(&self, key: &Key<N>, ciphertext: &[u8; M]) -> Result<Key<N>> {
        self.decrypt_aead(key, ciphertext)
    }

    fn generate_key(&self) -> Result<Key<N>> {
        self.generate_key_aead()
    }
}

/// Zero-sized generic provider type that can be used by concrete cipher modules.
pub struct AeadProvider<C>(PhantomData<C>);

impl<C> Default for AeadProvider<C> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature = "aes256-gcm")]
mod aes256_impl {
    use super::*;

    use aes_gcm::Aes256Gcm;

    pub type Aes256GcmProvider = AeadProvider<Aes256Gcm>;

    impl AeadCryptoProvider<32, 60> for Aes256GcmProvider {
        type Cipher = Aes256Gcm;
    }
}

#[cfg(feature = "aes256-gcm")]
pub use aes256_impl::Aes256GcmProvider;

#[cfg(feature = "xsalsa20-poly1305")]
mod xsalsa20_impl {
    use super::*;

    use crypto_secretbox::XSalsa20Poly1305;

    pub type XSalsa20Poly1305Provider = AeadProvider<XSalsa20Poly1305>;

    impl AeadCryptoProvider<32, 72> for XSalsa20Poly1305Provider {
        type Cipher = XSalsa20Poly1305;
    }
}

#[cfg(feature = "xsalsa20-poly1305")]
pub use xsalsa20_impl::XSalsa20Poly1305Provider;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoProvider, Error, Key};

    #[cfg(feature = "aes256-gcm")]
    mod aes256_tests {
        use super::*;

        #[test]
        fn aes256_generate_key_returns_32_bytes_and_is_random() {
            let provider = Aes256GcmProvider::default();

            let key1: Key<32> = provider.generate_key().expect("Failed to generate key");
            let key2: Key<32> = provider.generate_key().expect("Failed to generate key");

            assert_eq!(key1.len(), 32);
            assert_eq!(key2.len(), 32);
            assert_ne!(key1, key2);
        }

        #[test]
        fn aes256_encrypt_decrypt_round_trip() {
            let provider = Aes256GcmProvider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let encrypted: [u8; 60] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");
            let decrypted = provider
                .decrypt(&parent_key, &encrypted)
                .expect("Failed to decrypt");

            assert_eq!(encrypted.len(), 60);
            assert_eq!(data_key, decrypted);
        }

        #[test]
        fn aes256_encrypt_same_plaintext_twice_produces_distinct_ciphertexts() {
            let provider = Aes256GcmProvider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let encrypted1: [u8; 60] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");
            let encrypted2: [u8; 60] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");

            assert_ne!(encrypted1, encrypted2);

            let decrypted1 = provider
                .decrypt(&parent_key, &encrypted1)
                .expect("Failed to decrypt");
            let decrypted2 = provider
                .decrypt(&parent_key, &encrypted2)
                .expect("Failed to decrypt");

            assert_eq!(decrypted1, data_key);
            assert_eq!(decrypted2, data_key);
        }

        #[test]
        fn aes256_decrypt_with_wrong_parent_key_fails() {
            let provider = Aes256GcmProvider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let wrong_parent: Key<32> = provider
                .generate_key()
                .expect("Failed to generate wrong parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let encrypted: [u8; 60] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");

            let err = provider
                .decrypt(&wrong_parent, &encrypted)
                .expect_err("Decrypting with wrong parent key should fail");

            match err {
                Error::Crypto(_) => {}
                _ => panic!("Expected Error::Crypto for wrong-key decryption"),
            }
        }

        #[test]
        fn aes256_decrypt_tampered_ciphertext_fails() {
            let provider = Aes256GcmProvider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let mut encrypted: [u8; 60] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");

            encrypted[encrypted.len() - 1] ^= 0x01;

            let err = provider
                .decrypt(&parent_key, &encrypted)
                .expect_err("Decrypting tampered ciphertext should fail");

            match err {
                Error::Crypto(_) => {}
                _ => panic!("Expected Error::Crypto for tampered ciphertext"),
            }
        }
    }

    #[cfg(feature = "xsalsa20-poly1305")]
    mod xsalsa20_tests {
        use super::*;

        #[test]
        fn xsalsa20_generate_key_returns_32_bytes_and_is_random() {
            let provider = XSalsa20Poly1305Provider::default();

            let key1: Key<32> = provider.generate_key().expect("Failed to generate key");
            let key2: Key<32> = provider.generate_key().expect("Failed to generate key");

            assert_eq!(key1.len(), 32);
            assert_eq!(key2.len(), 32);
            assert_ne!(key1, key2);
        }

        #[test]
        fn xsalsa20_encrypt_decrypt_round_trip() {
            let provider = XSalsa20Poly1305Provider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let encrypted: [u8; 72] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");
            let decrypted = provider
                .decrypt(&parent_key, &encrypted)
                .expect("Failed to decrypt");

            assert_eq!(encrypted.len(), 72);
            assert_eq!(data_key, decrypted);
        }

        #[test]
        fn xsalsa20_decrypt_tampered_ciphertext_fails() {
            let provider = XSalsa20Poly1305Provider::default();
            let parent_key: Key<32> = provider
                .generate_key()
                .expect("Failed to generate parent key");
            let data_key: Key<32> = provider.generate_key().expect("Failed to generate data key");

            let mut encrypted: [u8; 72] = provider
                .encrypt(&parent_key, &data_key)
                .expect("Failed to encrypt");

            encrypted[encrypted.len() - 1] ^= 0x01;

            let err = provider
                .decrypt(&parent_key, &encrypted)
                .expect_err("Decrypting tampered ciphertext should fail");

            match err {
                Error::Crypto(_) => {}
                _ => panic!("Expected Error::Crypto for tampered ciphertext"),
            }
        }
    }
}
