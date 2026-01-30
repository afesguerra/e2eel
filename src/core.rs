use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptorError {
    #[error("No key found")]
    InvalidKeyID,
    #[error("No root key found")]
    InvalidRootKeyID,
    #[error("Invalid key size")]
    InvalidKeySize(usize),

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
type EncryptedKey = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGraph {
    pub version: String,
    pub roots: Vec<String>,
    pub nodes: HashMap<String, KeyNode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyNode {
    pub algo: String,
    pub wrappings: HashMap<String, EncryptedKey>,
}

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
        if !keys.roots.contains(&id.into()) {
            return Err(EncryptorError::InvalidKeyID);
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
        let encrypted_key = self
            .keys
            .nodes
            .get(id)
            .ok_or(EncryptorError::InvalidKeyID)?
            .wrappings
            .get(&self.current.0)
            .ok_or(EncryptorError::InvalidKeyID)?;

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
    use std::collections::HashMap;

    const ALGO: &'static str = "aes_gcm";
    const KEK_LABEL: &'static str = "kek";
    const MASTER_LABEL: &'static str = "master";
    const RECOVERY_LABEL: &'static str = "recovery";

    const MASTER_KEY: PlainKey = [0u8; 32];
    const RECOVERY_KEY: PlainKey = [1u8; 32];

    const PASSWORD: &[u8] = b"test_password";
    const SALT: &[u8] = b"test_salt";

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

    pub(crate) fn sample_graph() -> KeyGraph {
        KeyGraph {
            version: "0.1".to_string(),
            roots: vec![KEK_LABEL.to_string()],
            nodes: HashMap::from([
                (
                    MASTER_LABEL.to_string(),
                    KeyNode {
                        algo: ALGO.to_string(),
                        wrappings: HashMap::from([(
                            KEK_LABEL.to_string(),
                            vec![
                                69, 4, 131, 16, 243, 114, 55, 50, 143, 173, 62, 57, 1, 229, 144,
                                128, 129, 175, 17, 231, 1, 255, 154, 150, 142, 17, 185, 157, 246,
                                54, 238, 232, 106, 208, 172, 93, 101, 129, 118, 89, 214, 52, 65,
                                46, 125, 27, 124, 78, 87, 213, 49, 77, 21, 212, 98, 123, 164, 102,
                                21, 185,
                            ],
                        )]),
                    },
                ),
                (
                    RECOVERY_LABEL.to_string(),
                    KeyNode {
                        algo: ALGO.to_string(),
                        wrappings: HashMap::from([(
                            MASTER_LABEL.to_string(),
                            vec![
                                113, 94, 4, 21, 212, 215, 60, 86, 124, 33, 224, 244, 41, 8, 63, 99,
                                159, 79, 62, 168, 103, 43, 90, 189, 165, 44, 225, 170, 159, 175,
                                229, 65, 95, 177, 249, 29, 137, 123, 38, 224, 189, 84, 143, 73,
                                156, 126, 42, 147, 25, 204, 53, 112, 107, 102, 91, 246, 131, 162,
                                139, 151,
                            ],
                        )]),
                    },
                ),
            ]),
        }
    }
}
