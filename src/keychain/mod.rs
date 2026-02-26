use crate::{Error, Key, KeyGraph, Result};

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

pub struct KeyChain<G, C, const N: usize, const M: usize>
where
    G: KeyGraph,
    C: CryptoProvider<N, M>,
{
    keys: G,
    root_id: String,
    root: Key<N>,
    crypto: C,
}

impl<G, C, const N: usize, const M: usize> KeyChain<G, C, N, M>
where
    G: KeyGraph,
    C: CryptoProvider<N, M>,
{
    pub fn new(crypto: C, root_id: &str, root: Key<N>, keys: G) -> Result<Self> {
        Ok(Self {
            crypto,
            keys,
            root_id: root_id.into(),
            root,
        })
    }

    pub fn get_key(&self, id: &str) -> Result<Key<N>> {
        let path =
            self.keys
                .find_shortest_path(&self.root_id, id)
                .ok_or(Error::NoSuchPath(format!(
                    "There is no path from {} to {}",
                    self.root_id, id
                )))?;

        let mut key: Key<N> = self.root.clone();
        let mut key_id = &self.root_id;

        for node_id in &path[1..] {
            let encrypted_key: &[u8; M] = self.keys
                    .get_wrapping(node_id, key_id)
                    .ok_or(Error::InvalidWrapping(
                        node_id.clone(),
                        key_id.clone(),
                    ))?
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Generic(format!(
                        "Encrypted key for {} has incorrect length: expected {M} bytes",
                        node_id
                    )))?;

            key = self.crypto.decrypt(&key, encrypted_key)?;
            key_id = node_id;
        }

        Ok(key)
    }

    pub fn add_wrapping(&mut self, parent_id: &str, key_id: &str) -> Result<()> {
        let key = self.get_key(key_id).or_else(|_| self.crypto.generate_key())?;
        let parent = self.get_key(parent_id)?;

        let encrypted_key = self.crypto.encrypt(&parent, &key)?;

        self.keys.add_wrapping(key_id, parent_id, encrypted_key.as_ref())
    }

    pub fn add_root(&mut self, key_id: &str) -> Result<()> {
        self.keys.add_root(key_id)
    }

    pub fn get_graph(&self) -> &dyn KeyGraph {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::*;
    use crate::in_memory::InMemoryKeyGraph;
    use std::array::from_fn;

    const KEK: [u8; 32] = [0u8; 32];

    fn array_from_mul(mul: &u8) -> [u8; 32] {
        from_fn(|i| (i as u8) * mul)
    }

    #[test]
    fn test_create_graph() {
        let mut keychain = KeyChain::new(
            TestCrypto::new(),
            KEK_LABEL,
            Key::from(KEK),
            InMemoryKeyGraph::new(),
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
        assert_eq!(master_key, *keychain.get_key(MASTER_LABEL).unwrap());
        assert_eq!(recovery_key, *keychain.get_key(RECOVERY_LABEL).unwrap());

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
