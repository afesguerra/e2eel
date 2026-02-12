use aes_gcm::{
    AeadCore, Aes256Gcm,
    aead::{Aead, KeyInit, OsRng},
    aes::cipher::InvalidLength,
};

use crate::{CryptoProvider, Result};

pub struct Aes256GcmProvider;

impl CryptoProvider for Aes256GcmProvider {
    type Key = [u8; 32];
    type EncryptedKey = [u8; 60];

    fn generate_key(&self) -> Result<Self::Key> {
        let key = Aes256Gcm::generate_key(OsRng);
        Ok(key.into())
    }
    fn decrypt(&self, key: &Self::Key, data: &[u8]) -> Result<Self::Key> {
        let (nonce, ciphertext) = data.split_at(12);

        let result: Self::Key = Aes256Gcm::new(key.into())
            .decrypt(nonce.into(), ciphertext)?
            .try_into()
            .map_err(|_| InvalidLength)?;
        Ok(result)
    }

    fn encrypt(&self, parent: &Self::Key, data: &Self::Key) -> Result<Self::EncryptedKey> {
        let cipher = Aes256Gcm::new_from_slice(parent)?;
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = cipher.encrypt(&nonce, data.as_slice())?;

        let mut result = [0u8; 60];
        result[..12].copy_from_slice(&nonce);
        result[12..].copy_from_slice(&ciphertext);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::*;
    use crate::*;

    #[test]
    fn test_create_graph() {
        let mut keychain = KeyChain::<TestKeyStorage, Aes256GcmProvider>::new(
            TestKeyStorage {},
            Aes256GcmProvider {},
            KEK_LABEL,
            &KEK_PLAIN,
        )
        .expect("KeyChain creation failed");

        keychain
            .add_root(KEK_LABEL)
            .expect("Error adding KEK as root");
        keychain
            .add_wrapping(KEK_LABEL, MASTER_LABEL)
            .expect("Wrapping master failed");
        keychain
            .add_wrapping(MASTER_LABEL, RECOVERY_LABEL)
            .expect("Wrapping recovery failed");
    }

    #[test]
    fn test_sample_graph() {
        let mut keychain = KeyChain::<TestKeyStorage, Aes256GcmProvider>::new(
            TestKeyStorage {},
            Aes256GcmProvider {},
            KEK_LABEL,
            &KEK_PLAIN,
        )
        .unwrap();

        keychain.fetch().expect("Failed to fetch key graph");

        let master_key = keychain.get_key(MASTER_LABEL).unwrap();
        let recovery_key = keychain.get_key(RECOVERY_LABEL).unwrap();

        assert_eq!(master_key, MASTER_KEY_PLAIN);
        assert_eq!(recovery_key, RECOVERY_KEY_PLAIN);
    }
}
