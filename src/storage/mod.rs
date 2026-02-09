#[cfg(feature = "json")]
pub mod json;

use crate::{Result, KeyGraph};

pub trait KeyStorage {
    fn load(&self) -> Result<KeyGraph>;
    fn save(&self, keys: &KeyGraph) -> Result<()>;
}
