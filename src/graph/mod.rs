use crate::Result;

mod in_memory;

pub use in_memory::InMemoryKeyGraph;

/// Trait defining the interface for a key graph structure.
/// A key graph manages key wrappings and parent-child relationships between keys.
pub trait KeyGraph {
    /// Checks if the given ID is a root key.
    fn has_root(&self, id: &str) -> bool;

    /// Adds a new root key to the graph.
    fn add_root(&mut self, id: &str) -> Result<()>;

    /// Adds a wrapping of a key under a parent key.
    fn add_wrapping(&mut self, id: &str, parent: &str, data: &[u8]) -> Result<()>;

    /// Retrieves the wrapping of a key for a specific parent.
    fn get_wrapping(&self, id: &str, parent: &str) -> Option<&Vec<u8>>;

    /// Finds the shortest path between two key IDs in the graph.
    fn find_shortest_path(&self, src: &str, dest: &str) -> Option<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::*;

    #[test]
    fn test_shortest_path() {
        let graph = sample_graph();

        let shortest_path = graph
            .find_shortest_path(KEK_LABEL, RECOVERY_LABEL)
            .expect("Cannot find path between KEK and RECOVERY");

        assert_eq!(
            shortest_path,
            vec![
                KEK_LABEL.to_string(),
                MASTER_LABEL.to_string(),
                RECOVERY_LABEL.to_string()
            ]
        );
    }

    #[test]
    fn test_multiple_paths() {
        let mock_data = [0u8; 1];
        let mut graph = InMemoryKeyGraph::new();

        graph.add_root("root").unwrap();
        graph.add_wrapping("nodeA1", "root", &mock_data).unwrap();
        graph.add_wrapping("nodeB1", "root", &mock_data).unwrap();

        graph.add_wrapping("nodeA2", "nodeA1", &mock_data).unwrap();
        graph.add_wrapping("nodeC", "nodeA2", &mock_data).unwrap();
        graph.add_wrapping("nodeC", "nodeB1", &mock_data).unwrap();

        assert_eq!(
            vec!["root", "nodeB1", "nodeC"],
            graph.find_shortest_path("root", "nodeC").unwrap()
        )
    }
}
