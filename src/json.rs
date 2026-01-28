use crate::core::{KeyStorage, KeyGraph, Result};

pub struct JsonStorage {
    path: String,
}

impl JsonStorage {
    pub fn new(path: String) -> Self {
        JsonStorage { path }
    }
}

impl KeyStorage for JsonStorage {
    fn load(&self) -> Result<KeyGraph> {
        let json = std::fs::read_to_string(&self.path)?;
        println!("Loaded JSON: {}", json);
        Ok(serde_json::from_str(&json)?)
    }

    fn save(&self, keys: &KeyGraph) -> Result<()> {
        let json = serde_json::to_string_pretty(keys)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::sample_graph;

    #[test]
    fn test_load_json() {
        let key_chain = JsonStorage::new("testdata/serde.json".to_string());
        let result = key_chain.load();
        print!("Result {:?}", result);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    #[ignore = "Used to generate new test file"]
    fn test_save_json() {
        let keys = sample_graph();

        let key_chain = JsonStorage::new("testdata/serde.json".to_string());
        println!("KeyTree: {:?}", keys);
        let result = key_chain.save(&keys);
        assert_eq!(result.is_ok(), true);
    }
}
