use crate::in_memory::InMemoryKeyGraph;
use crate::{CryptoProvider, Key, KeyGraph, Result};

use std::array::from_fn;
use std::sync::atomic::{AtomicU8, Ordering};

pub const KEK_LABEL: &str = "kek";
pub const MASTER_LABEL: &str = "master";
pub const RECOVERY_LABEL: &str = "recovery";

fn array_from_mul(mul: &u8) -> [u8; 32] {
    from_fn(|i| (i as u8) * mul)
}

pub struct TestCrypto(AtomicU8);

impl TestCrypto {
    pub fn new() -> Self {
        Self(AtomicU8::new(1))
    }
}

const KEY_SIZE: usize = 32;

impl CryptoProvider<KEY_SIZE, KEY_SIZE> for TestCrypto {
    fn generate_key(&self) -> Result<Key<32>> {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        Ok(Key::from(array_from_mul(&n)))
    }

    fn encrypt(&self, _key: &[u8; KEY_SIZE], plaintext: &[u8; KEY_SIZE]) -> Result<[u8; KEY_SIZE]> {
        let mut data = *plaintext;
        data.reverse();
        Ok(data)
    }

    fn decrypt(&self, _key: &[u8; KEY_SIZE], ciphertext: &[u8; KEY_SIZE]) -> Result<Key<KEY_SIZE>> {
        let mut data: [u8; KEY_SIZE] = *ciphertext;
        data.reverse();
        Ok(Key::from(data))
    }
}

pub const MASTER_KEY: [u8; 60] = [
    69, 4, 131, 16, 243, 114, 55, 50, 143, 173, 62, 57, 1, 229, 144, 128, 129, 175, 17, 231, 1,
    255, 154, 150, 142, 17, 185, 157, 246, 54, 238, 232, 106, 208, 172, 93, 101, 129, 118, 89, 214,
    52, 65, 46, 125, 27, 124, 78, 87, 213, 49, 77, 21, 212, 98, 123, 164, 102, 21, 185,
];

pub const RECOVERY_KEY: [u8; 60] = [
    113, 94, 4, 21, 212, 215, 60, 86, 124, 33, 224, 244, 41, 8, 63, 99, 159, 79, 62, 168, 103, 43,
    90, 189, 165, 44, 225, 170, 159, 175, 229, 65, 95, 177, 249, 29, 137, 123, 38, 224, 189, 84,
    143, 73, 156, 126, 42, 147, 25, 204, 53, 112, 107, 102, 91, 246, 131, 162, 139, 151,
];

pub fn sample_graph() -> InMemoryKeyGraph {
    let mut graph = InMemoryKeyGraph::default();
    graph.add_root(KEK_LABEL).unwrap();
    graph
        .add_wrapping(KEK_LABEL, MASTER_LABEL, &MASTER_KEY)
        .unwrap();
    graph
        .add_wrapping(MASTER_LABEL, RECOVERY_LABEL, &RECOVERY_KEY)
        .unwrap();
    graph
}
