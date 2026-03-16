use serde::{Serialize, de::DeserializeOwned};

use super::KeyGraph;
use crate::Result;

pub mod local;

pub trait GraphRepository {
    fn save<P: KeyGraph + Serialize>(&self, graph: &P) -> Result<()>;
    fn load<P: KeyGraph + DeserializeOwned>(&self) -> Result<P>;
}

#[cfg(test)]
mod tests {
    use super::{GraphRepository};
    use super::local::JsonLocalRepository;
    use crate::in_memory::InMemoryKeyGraph;
    use crate::test_data::sample_graph;

    const PATH: &str = "tmp/serde.json";

    #[test]
    fn test_json() {
        test_serialization(JsonLocalRepository::new(PATH));
    }

    fn test_serialization<P: GraphRepository>(p: P) {
        use std::fs::{create_dir_all, metadata, remove_file};

        // Clean up any existing file
        let _ = remove_file(PATH);
        create_dir_all("tmp").expect("Unable to create tmp dir");

        let graph = sample_graph();

        // Test save
        p.save(&graph).expect("Error saving graph");

        // Verify file exists
        assert!(metadata(PATH).is_ok());

        // Test load
        let loaded = p
            .load::<InMemoryKeyGraph>()
            .expect("Unable to load graph");
        assert_eq!(loaded, graph);

        // Clean up
        let _ = remove_file(PATH);
    }
}
