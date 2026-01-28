use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptorError {
    #[error("No key found")]
    NoKey,

    // Dependencies
    #[error("Crypto error")]
    Crypto(#[from] argon2::Error),
    #[error("JSON (de)serialization error")]
    JSON(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    // Add more...
}

pub type Result<T> = std::result::Result<T, EncryptorError>;
type Key = Vec<u8>;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGraph {
    pub version: String,
    pub roots: Vec<String>,
    pub nodes: HashMap<String, KeyNode>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyNode {
    pub algo: String,
    pub wrappings: HashMap<String, Key>,
}

pub trait KeyStorage {
    fn load(&self) -> Result<KeyGraph>;
    fn save(&self, keys: &KeyGraph) -> Result<()>;
}

#[derive(Debug)]
pub struct KeyChain<'a> {
    keys: &'a KeyGraph,
    current: PlainKey,
}

#[derive(Debug)]
struct PlainKey(String, Key);

impl<'a> KeyChain<'a> {
    pub fn new(keys: &'a KeyGraph, id: &str, password: &[u8], salt: &[u8]) -> Result<Self> {
        // Derive KEK with Argon2id (add argon2 crate)
        let mut kek = [0u8; 32];
        Argon2::default().hash_password_into(password, salt, &mut kek)?;

        Ok(Self {
            keys: &keys,
            current: PlainKey(id.to_string(), kek.into()),
        })
    }

    pub fn with(&self, id: &str) -> Result<Self> {
        let target = self
            .keys
            .nodes
            .get(&id.to_string())
            .ok_or(EncryptorError::NoKey)?
            .wrappings
            .get(&self.current.0.to_string())
            .ok_or(EncryptorError::NoKey)?;
        Ok(KeyChain {
            keys: self.keys,
            current: PlainKey(id.to_string(), target.to_vec()),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    const ALGO_ARGON: &str = "argon2id";
    const KEK: &str = "kek";
    const RECOVERY: &str = "recovery";
    const MASTER: &str = "master";

    const PASSWORD: &[u8] = b"test_password";
    const SALT: &[u8] = b"test_salt";

    #[test]
    fn test_sample_graph() -> Result<()> {
        let graph = sample_graph();
        let keychain = KeyChain::new(&graph, KEK, PASSWORD, SALT)?;

        println!("Keychain {:?}", keychain);
        println!("Keychain {:?}", keychain.with("master")?);
        Ok(())
    }

    pub(crate) fn sample_graph() -> KeyGraph {
        KeyGraph {
            version: "0.1".to_string(),
            roots: vec![KEK.to_string(), RECOVERY.to_string()],
            nodes: HashMap::from([
                (
                    MASTER.to_string(),
                    KeyNode {
                        algo: ALGO_ARGON.to_string(),
                        wrappings: HashMap::from([
                            (KEK.to_string(), vec![0u8; 32]),
                            (RECOVERY.to_string(), vec![1u8; 32]),
                        ]),
                    },
                ),
                (
                    RECOVERY.to_string(),
                    KeyNode {
                        algo: ALGO_ARGON.to_string(),
                        wrappings: HashMap::from([(MASTER.to_string(), vec![2u8; 32])]),
                    },
                ),
            ]),
        }
    }
}
