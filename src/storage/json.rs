use std::fs::{read_to_string, write};

use super::{KeyGraph, KeyStorage};
use crate::core::Result;

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
        let json = read_to_string(&self.path)?;
        Ok(serde_json::from_str(&json)?)
    }

    fn save(&self, keys: &KeyGraph) -> Result<()> {
        let json = serde_json::to_string_pretty(keys)?;
        write(&self.path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, exists, remove_file};

    use super::*;
    use crate::test_data::sample_graph;

    const JSON_PATH: &str = "tmp/serde.json";

    #[test]
    fn test_save_and_load() {
        if exists(JSON_PATH).expect("Error checking file") {
            remove_file(JSON_PATH).expect("Error removing file");
        }

        create_dir_all("tmp").unwrap();

        let key_chain = JsonStorage::new(JSON_PATH.to_string());

        let graph = sample_graph();
        key_chain.save(&graph).expect("Error saving graph");

        let file_exists = exists(JSON_PATH).expect("Error checking file");
        assert_eq!(file_exists, true);

        let result = key_chain.load().expect("Unable to load graph");
        assert_eq!(result, graph);
    }
}
