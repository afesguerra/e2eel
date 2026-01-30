mod json;

use crate::core::{KeyGraph, Result};
pub use json::JsonStorage;

pub trait KeyStorage {
    fn load(&self) -> Result<KeyGraph>;
    fn save(&self, keys: &KeyGraph) -> Result<()>;
}
