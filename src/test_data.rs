use aes_gcm::aes::cipher::InvalidLength;

use super::*;
use std::array::from_fn;
use std::sync::atomic::{AtomicU8, Ordering};

pub const KEK_LABEL: &str = "kek";
pub const MASTER_LABEL: &str = "master";
pub const RECOVERY_LABEL: &str = "recovery";

pub const MASTER_KEY_PLAIN: [u8; 32] = [0u8; 32];
pub const RECOVERY_KEY_PLAIN: [u8; 32] = [1u8; 32];

pub const KEK_PLAIN: [u8; 32] = [
    199, 38, 76, 248, 232, 20, 77, 19, 252, 96, 76, 89, 136, 183, 188, 134, 189, 54, 116, 38, 238,
    35, 79, 177, 113, 98, 225, 174, 87, 35, 113, 98,
];

const MASTER_KEY: [u8; 60] = [
    69, 4, 131, 16, 243, 114, 55, 50, 143, 173, 62, 57, 1, 229, 144, 128, 129, 175, 17, 231, 1,
    255, 154, 150, 142, 17, 185, 157, 246, 54, 238, 232, 106, 208, 172, 93, 101, 129, 118, 89, 214,
    52, 65, 46, 125, 27, 124, 78, 87, 213, 49, 77, 21, 212, 98, 123, 164, 102, 21, 185,
];

const RECOVERY_KEY: [u8; 60] = [
    113, 94, 4, 21, 212, 215, 60, 86, 124, 33, 224, 244, 41, 8, 63, 99, 159, 79, 62, 168, 103, 43,
    90, 189, 165, 44, 225, 170, 159, 175, 229, 65, 95, 177, 249, 29, 137, 123, 38, 224, 189, 84,
    143, 73, 156, 126, 42, 147, 25, 204, 53, 112, 107, 102, 91, 246, 131, 162, 139, 151,
];

pub struct TestKeyStorage;

impl KeyStorage for TestKeyStorage {
    fn load(&self) -> Result<KeyGraph> {
        Ok(sample_graph())
    }

    fn save(&self, _keys: &KeyGraph) -> Result<()> {
        todo!()
    }
}

pub fn array_from_mul(mul: &u8) -> [u8; 32] {
    from_fn(|i| (i as u8) * mul)
}

pub struct TestCrypto;

static COUNTER: AtomicU8 = AtomicU8::new(1);

impl CryptoProvider for TestCrypto {
    type Key = [u8; 32];
    type EncryptedKey = Self::Key;

    fn generate_key(&self) -> Result<Self::Key> {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data = array_from_mul(&n);
        Ok(data)
    }

    fn encrypt(&self, _key: &Self::Key, plaintext: &Self::Key) -> Result<Self::EncryptedKey> {
        let mut data = plaintext.clone();
        data.reverse();
        Ok(data)
    }

    fn decrypt(&self, _key: &Self::Key, ciphertext: &[u8]) -> Result<Self::Key> {
        let mut data: Self::Key = ciphertext.try_into().map_err(|_| InvalidLength)?;
        data.reverse();
        Ok(data)
    }
}

pub fn sample_graph() -> KeyGraph {
    let mut graph = KeyGraph::new();

    graph.add_root(KEK_LABEL).unwrap();
    graph
        .add_wrapping(MASTER_LABEL, KEK_LABEL, &MASTER_KEY)
        .unwrap();
    graph
        .add_wrapping(RECOVERY_LABEL, MASTER_LABEL, &RECOVERY_KEY)
        .unwrap();
    graph
}
