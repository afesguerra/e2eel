use crate::{KeyStorage, storage::KeyGraph};
use argon2::Argon2;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptorError {
    #[error("No wrapping found for key {0} and parent {1}")]
    InvalidWrapping(String, String),
    #[error("Key {0} not found")]
    InvalidKeyID(String),
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

pub struct KeyChain<S: KeyStorage> {
    storage: S,
    keys: KeyGraph,
    root_id: String,
    root: Vec<u8>,
}

impl<S: KeyStorage> KeyChain<S> {
    pub fn new(storage: S, root: &str, password: &[u8], salt: &[u8]) -> Result<Self> {
        let keys = storage.load()?;
        if !keys.has_root(root) {
            return Err(EncryptorError::InvalidKeyID(root.into()));
        }

        // Derive KEK with Argon2id (add argon2 crate)
        let mut kek = [0u8; 32];
        Argon2::default().hash_password_into(password, salt, &mut kek)?;

        Ok(Self {
            storage: storage,
            keys,
            root_id: root.to_string(),
            root: kek.into(),
        })
    }

    pub fn get_key(&self, id: &str) -> Result<Vec<u8>> {
        let path = self
            .keys
            .find_shortest_path(&self.root_id, id)
            .ok_or(EncryptorError::TBD)?;

        let mut key = self.root.clone();
        let mut key_id = &self.root_id;

        for node_id in &path[1..] {
            let encrypted_key =
                self.keys
                    .get_wrapping(node_id, &key_id)
                    .ok_or(EncryptorError::InvalidWrapping(
                        node_id.clone(),
                        key_id.clone(),
                    ))?;

            key = self.decrypt(&key, encrypted_key)?;
            key_id = node_id;
        }

        Ok(key)
    }

    pub fn add_wrapping(&mut self, parent_id: &str, key_id: &str) -> Result<()> {
        let key = self.new_key()?;
        let parent = self.get_key(parent_id)?;

        let encrypted_key = self._encrypt(&parent, &key)?;

        self.keys
            .add_wrapping(key_id, "algorithm_TBD", parent_id, &encrypted_key)
    }

    pub fn reload(&mut self) -> Result<()> {
        self.keys = self.storage.load()?;
        Ok(())
    }

    pub fn persist(&mut self) -> Result<()> {
        self.storage.save(&self.keys)
    }

    fn new_key(&self) -> Result<Vec<u8>> {
        use aes_gcm::aead::KeyInit;
        use aes_gcm::{Aes256Gcm, aead::OsRng};

        let key = Aes256Gcm::generate_key(OsRng);
        Ok(key.to_vec())
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            Aes256Gcm,
            aead::{Aead, KeyInit},
        };

        let (nonce, ciphertext) = data.split_at(12);

        Aes256Gcm::new(key.into())
            .decrypt(nonce.into(), ciphertext)
            .map_err(EncryptorError::Crypto)
    }

    fn _encrypt(&self, parent: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            AeadCore, Aes256Gcm,
            aead::{Aead, KeyInit, OsRng},
        };

        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let cipher = Aes256Gcm::new_from_slice(parent).map_err(|_| EncryptorError::TBD)?;

        let ciphertext = cipher
            .encrypt(&nonce, data)
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

    struct TestKeyStorage {}

    impl TestKeyStorage {
        fn new() -> Self {
            Self {}
        }
    }

    impl KeyStorage for TestKeyStorage {
        fn load(&self) -> Result<KeyGraph> {
            Ok(sample_graph())
        }

        fn save(&self, _keys: &KeyGraph) -> Result<()> {
            todo!()
        }
    }

    #[test]
    fn test_sample_graph() {
        let keychain =
            KeyChain::<TestKeyStorage>::new(TestKeyStorage::new(), KEK_LABEL, PASSWORD, SALT)
                .unwrap();

        let master_key = keychain.get_key(MASTER_LABEL).unwrap();
        let recovery_key = keychain.get_key(RECOVERY_LABEL).unwrap();

        assert_eq!(master_key, MASTER_KEY);
        assert_eq!(recovery_key, RECOVERY_KEY);
    }
}
