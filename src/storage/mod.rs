#[cfg(feature = "json")]
pub mod json;

use crate::{Result, KeyGraph};

pub trait KeyStorage {
    fn load(&self) -> Result<KeyGraph>;
    fn save(&mut self, keys: &KeyGraph) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MemoryStorage(KeyGraph);

    impl KeyStorage for MemoryStorage {
        fn load(&self) -> Result<KeyGraph> {
            Ok(self.0.clone())
        }

        fn save(&mut self, keys: &KeyGraph) -> Result<()> {
            self.0 = keys.clone();
            Ok(())
        }
    }

    #[test]
    fn test_load() {
        let storage = MemoryStorage(KeyGraph::new());
        let result = storage.load();
        assert!(result.is_ok());
    }

    #[test]
    fn test_save() {
        let mut storage = MemoryStorage(KeyGraph::new());
        let result = storage.save(&KeyGraph::new());
        assert!(result.is_ok());
    }
}
