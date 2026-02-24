#[cfg(feature = "json")]
pub mod json;

use crate::{Result, graph::InMemoryKeyGraph};

pub trait KeyStorage {
    fn load(&self) -> Result<InMemoryKeyGraph>;
    fn save(&mut self, keys: &InMemoryKeyGraph) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MemoryStorage(InMemoryKeyGraph);

    impl KeyStorage for MemoryStorage {
        fn load(&self) -> Result<InMemoryKeyGraph> {
            Ok(self.0.clone())
        }

        fn save(&mut self, keys: &InMemoryKeyGraph) -> Result<()> {
            self.0 = keys.clone();
            Ok(())
        }
    }

    #[test]
    fn test_load() {
        let storage = MemoryStorage(InMemoryKeyGraph::new());
        let result = storage.load();
        assert!(result.is_ok());
    }

    #[test]
    fn test_save() {
        let mut storage = MemoryStorage(InMemoryKeyGraph::new());
        let result = storage.save(&InMemoryKeyGraph::new());
        assert!(result.is_ok());
    }
}
