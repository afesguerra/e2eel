use crate::storage::KeyGraph;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptorError {
    #[error("No wrapping found for key {0} and parent {1}")]
    InvalidWrapping(String, String),
    #[error("No root key found")]
    InvalidRootKeyID(String),
    #[error("Parent key ID is not in graph")]
    InvalidParentKeyID(String),
    #[error("Invalid key size")]
    InvalidKeySize(usize),
    #[error("TBD")]
    TBD,

    // Dependencies
    #[error("PBKDF error")]
    PBKDF(#[from] argon2::Error),
    #[error("Crypto error")]
    Crypto(aes_gcm::Error),
    #[error("JSON (de)serialization error")]
    JSON(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    // Add more...
}

pub type Result<T> = std::result::Result<T, EncryptorError>;

#[derive(Debug)]
pub struct KeyChain<'a> {
    keys: &'a KeyGraph,
    current: PlainKeyWrap,
}

type PlainKey = [u8; 32];

#[derive(Debug, Clone)]
struct PlainKeyWrap(String, PlainKey);

impl PlainKeyWrap {
    /// Generate cryptographically secure AES-256 key
    #[cfg(test)]
    fn generate_aes256(id: &str) -> Self {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes); // 256-bit secure random
        Self(id.to_string(), key_bytes)
    }

    /// Generate from seed (deterministic, testing only)
    #[cfg(test)]
    fn from_seed_aes256(id: &str, seed: &[u8; 32]) -> Self {
        Self(id.to_string(), seed.clone())
    }
}

impl<'graph> KeyChain<'graph> {
    pub fn new(keys: &'graph KeyGraph, id: &str, password: &[u8], salt: &[u8]) -> Result<Self> {
        if !keys.has_root(id) {
            return Err(EncryptorError::InvalidRootKeyID(id.into()));
        }

        // Derive KEK with Argon2id (add argon2 crate)
        let mut kek = [0u8; 32];
        Argon2::default().hash_password_into(password, salt, &mut kek)?;

        Ok(Self {
            keys: keys,
            current: PlainKeyWrap(id.to_string(), kek.into()),
        })
    }

    #[cfg(test)]
    fn with_seed(&self, seed: &PlainKeyWrap) -> Result<Self> {
        Ok(Self {
            keys: self.keys,
            current: seed.clone(),
        })
    }

    pub fn with(&self, id: &str) -> Result<Self> {
        let encrypted_key =
            self.keys
                .get_wrapping(id, &self.current.0)
                .ok_or(EncryptorError::InvalidWrapping(
                    id.to_string(),
                    self.current.0.clone(),
                ))?;

        let key: PlainKey = self.decrypt(encrypted_key)?;

        Ok(KeyChain {
            keys: self.keys,
            current: PlainKeyWrap(id.to_string(), key),
        })
    }

    fn vec_to_plain_key(vec: Vec<u8>) -> Result<PlainKey> {
        vec.try_into()
            .map_err(|vec: Vec<u8>| EncryptorError::InvalidKeySize(vec.len()))
    }

    fn decrypt(&self, data: &[u8]) -> Result<PlainKey> {
        let key = self.current.1.clone();
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        Self::vec_to_plain_key(
            cipher
                .decrypt(&nonce, ciphertext)
                .map_err(EncryptorError::Crypto)?,
        )
    }

    #[cfg(test)]
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = &self.current.1;
        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(key));

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce); // Fresh random nonce!
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(EncryptorError::Crypto)?;

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::storage::tests::{KEK_LABEL, MASTER_LABEL, RECOVERY_LABEL, sample_graph};

    const PASSWORD: &[u8] = b"test_password";
    const SALT: &[u8] = b"test_salt";

    const MASTER_KEY: [u8; 32] = [0u8; 32];
    const RECOVERY_KEY: [u8; 32] = [1u8; 32];

    #[test]
    fn test_sample_graph() {
        let graph = sample_graph();

        let keychain = KeyChain::new(&graph, KEK_LABEL, PASSWORD, SALT).unwrap();
        let master_keychain = keychain.with(MASTER_LABEL).unwrap();
        let recovery_keychain = master_keychain.with(RECOVERY_LABEL).unwrap();

        assert_eq!(master_keychain.current.1, MASTER_KEY);
        assert_eq!(recovery_keychain.current.1, RECOVERY_KEY);
    }

    #[test]
    #[ignore = "Utility used to generate sample graph"]
    fn test_generate_aes256() {
        let graph = sample_graph();
        let keychain = KeyChain::new(&graph, KEK_LABEL, PASSWORD, SALT).unwrap();

        let master = PlainKeyWrap::from_seed_aes256(MASTER_LABEL, &MASTER_KEY);
        let recovery = PlainKeyWrap::from_seed_aes256(RECOVERY_LABEL, &RECOVERY_KEY);
        let new_key_chain = keychain.with_seed(&master).unwrap();

        let master_encrypted = keychain.encrypt(&master.1).unwrap();
        let child_encrypted = new_key_chain.encrypt(&recovery.1).unwrap();

        println!("Master: {:?}", master_encrypted);
        println!("Child: {:?}", child_encrypted);
        assert_eq!(master.1.len(), 32);
    }
}
