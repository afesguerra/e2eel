use crate::{EncryptorError, KeyGraph, KeyStorage, Result};

#[cfg(feature = "aes256-gcm")]
pub mod aes256;

/// Trait for encryption/decryption implementations
pub trait CryptoProvider: Send + Sync {
    type Key: AsRef<[u8]> + Clone;
    type EncryptedKey: AsRef<[u8]> + Clone;

    /// Encrypt data with a key
    fn encrypt(&self, key: &Self::Key, plaintext: &Self::Key) -> Result<Self::EncryptedKey>;
    /// Decrypt data with a key
    fn decrypt(&self, key: &Self::Key, ciphertext: &[u8]) -> Result<Self::Key>;
    /// Generate a new encryption key
    fn generate_key(&self) -> Result<Self::Key>;
}

pub struct KeyChain<S, C>
where
    S: KeyStorage,
    C: CryptoProvider,
{
    storage: S,
    keys: KeyGraph,
    root_id: String,
    root: C::Key,
    crypto: C,
}

impl<S, C> KeyChain<S, C>
where
    S: KeyStorage,
    C: CryptoProvider,
{
    pub fn new(storage: S, crypto: C, root_id: &str, root: &C::Key) -> Result<Self> {
        Ok(Self {
            storage,
            crypto,
            keys: KeyGraph::new(),
            root_id: root_id.into(),
            root: root.clone(),
        })
    }

    pub fn get_key(&self, id: &str) -> Result<C::Key> {
        let path =
            self.keys
                .find_shortest_path(&self.root_id, id)
                .ok_or(EncryptorError::NoSuchPath(format!(
                    "There is no path from {} to {}",
                    self.root_id, id
                )))?;

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

            key = self.crypto.decrypt(&key, encrypted_key)?;
            key_id = node_id;
        }

        Ok(key)
    }

    pub fn add_wrapping(&mut self, parent_id: &str, key_id: &str) -> Result<()> {
        let key = self.crypto.generate_key()?;
        let parent = self.get_key(parent_id)?;

        let encrypted_key = self.crypto.encrypt(&parent, &key)?;

        self.keys.add_wrapping(key_id, parent_id, encrypted_key.as_ref())
    }

    pub fn add_root(&mut self, key_id: &str) -> Result<()> {
        self.keys.add_root(key_id)
    }

    pub fn fetch(&mut self) -> Result<()> {
        self.keys = self.storage.load()?;
        Ok(())
    }

    pub fn persist(&mut self) -> Result<()> {
        self.storage.save(&self.keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::*;
    use std::array::from_fn;

    const KEK: [u8; 32] = [0u8; 32];

    fn array_from_mul(mul: &u8) -> [u8; 32] {
        from_fn(|i| (i as u8) * mul)
    }

    #[test]
    fn test_create_graph() {
        let mut keychain = KeyChain::<TestKeyStorage, TestCrypto>::new(
            TestKeyStorage {},
            TestCrypto {},
            KEK_LABEL,
            &KEK,
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

        let mut master_key = array_from_mul(&1);
        let mut recovery_key = array_from_mul(&2);
        assert_eq!(master_key.to_vec(), keychain.get_key(MASTER_LABEL).unwrap());
        assert_eq!(
            recovery_key.to_vec(),
            keychain.get_key(RECOVERY_LABEL).unwrap()
        );

        master_key.reverse();
        recovery_key.reverse();

        assert_eq!(
            master_key,
            keychain
                .keys
                .get_wrapping(MASTER_LABEL, KEK_LABEL)
                .unwrap()
                .clone()
                .as_mut_slice()
        );
        assert_eq!(
            recovery_key,
            keychain
                .keys
                .get_wrapping(RECOVERY_LABEL, MASTER_LABEL)
                .unwrap()
                .clone()
                .as_mut_slice()
        );
    }
}
