use crypto_secretbox::{
    XSalsa20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::{CryptoProvider, Error, Result};

pub struct XSalsa20Poly1305Provider;

impl CryptoProvider for XSalsa20Poly1305Provider {
    type Key = [u8; 32];
    type EncryptedKey = [u8; 72]; // 24 bytes nonce + 32 bytes ciphertext + 16 bytes tag

    fn generate_key(&self) -> Result<Self::Key> {
        let key = XSalsa20Poly1305::generate_key(OsRng);
        Ok(key.into())
    }

    fn decrypt(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Key> {
        let (nonce, ciphertext) = data.split_at(24);

        let result: Self::Key = XSalsa20Poly1305::new(key.into())
            .decrypt(nonce.into(), ciphertext)?
            .try_into()
            .map_err(|_| Error::Generic("Decrypted data has incorrect length".to_string()))?;
        Ok(result)
    }

    fn encrypt(&self, parent: &Self::Key, data: &Self::Key) -> Result<Self::EncryptedKey> {
        let cipher = XSalsa20Poly1305::new(parent.into());
        let nonce = XSalsa20Poly1305::generate_nonce(OsRng);
        let ciphertext = cipher.encrypt(&nonce, data.as_slice())?;

        let mut result = [0u8; 72];
        result[..24].copy_from_slice(&nonce);
        result[24..].copy_from_slice(&ciphertext);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let provider = XSalsa20Poly1305Provider {};
        let key1 = provider.generate_key().expect("Failed to generate key");
        let key2 = provider.generate_key().expect("Failed to generate key");

        // Keys should be 32 bytes
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // Keys should be different (extremely unlikely to be the same)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let provider = XSalsa20Poly1305Provider {};
        let parent_key = provider.generate_key().expect("Failed to generate parent key");
        let data_key = provider.generate_key().expect("Failed to generate data key");

        let encrypted = provider.encrypt(&parent_key, &data_key).expect("Failed to encrypt");
        let decrypted = provider.decrypt(&parent_key, &encrypted).expect("Failed to decrypt");

        // Encrypted data should be 72 bytes (24 nonce + 48 ciphertext+tag)
        assert_eq!(encrypted.len(), 72);
        
        // Decrypted data should match original
        assert_eq!(data_key, decrypted);
    }

    #[test]
    fn test_encrypt_produces_different_outputs() {
        let provider = XSalsa20Poly1305Provider {};
        let parent_key = provider.generate_key().expect("Failed to generate parent key");
        let data_key = provider.generate_key().expect("Failed to generate data key");

        let encrypted1 = provider.encrypt(&parent_key, &data_key).expect("Failed to encrypt");
        let encrypted2 = provider.encrypt(&parent_key, &data_key).expect("Failed to encrypt");

        // Due to random nonce, encrypted outputs should be different
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt to the same value
        let decrypted1 = provider.decrypt(&parent_key, &encrypted1).expect("Failed to decrypt");
        let decrypted2 = provider.decrypt(&parent_key, &encrypted2).expect("Failed to decrypt");
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(data_key, decrypted1);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let provider = XSalsa20Poly1305Provider {};
        let parent_key1 = provider.generate_key().expect("Failed to generate parent key 1");
        let parent_key2 = provider.generate_key().expect("Failed to generate parent key 2");
        let data_key = provider.generate_key().expect("Failed to generate data key");

        let encrypted = provider.encrypt(&parent_key1, &data_key).expect("Failed to encrypt");
        let result = provider.decrypt(&parent_key2, &encrypted);

        // Decryption with wrong key should fail
        assert!(result.is_err());
    }
}
