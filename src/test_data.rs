use super::*;
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

impl CryptoProvider<32, 32> for TestCrypto {
    fn generate_key(&self) -> Result<Key<32>> {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        Ok(Key::from(array_from_mul(&n)))
    }

    fn encrypt(&self, _key: &Key<32>, plaintext: &Key<32>) -> Result<[u8; 32]> {
        let mut data = **plaintext;
        data.reverse();
        Ok(data)
    }

    fn decrypt(&self, _key: &Key<32>, ciphertext: &[u8; 32]) -> Result<Key<32>> {
        let mut data: [u8; 32] = *ciphertext;
        data.reverse();
        Ok(Key::from(data))
    }
}