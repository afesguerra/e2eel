use super::*;
use std::array::from_fn;
use std::sync::atomic::{AtomicU8, Ordering};

pub const KEK_LABEL: &str = "kek";
pub const MASTER_LABEL: &str = "master";
pub const RECOVERY_LABEL: &str = "recovery";

fn array_from_mul(mul: &u8) -> [u8; 32] {
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
        let mut data: Self::Key = ciphertext
            .try_into()
            .expect("Cannot convert cipherText into Key");
        data.reverse();
        Ok(data)
    }
}
