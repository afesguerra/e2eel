use crate::Result;

pub mod in_memory;

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
