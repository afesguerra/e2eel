use std::borrow::Cow;

use crate::Result;

#[cfg(feature = "in-memory")]
pub mod in_memory;
#[cfg(feature = "in-memory")]
pub mod repository;

/// Trait defining the interface for a key graph structure.
/// A key graph manages key wrappings and parent-child relationships between keys.
pub trait KeyGraph {
    /// Adds a new root key to the graph.
    fn add_root(&mut self, id: &str) -> Result<()>;

    /// Adds a wrapping of a key under a parent key.
    fn add_wrapping(&mut self, parent: &str, id: &str, data: &[u8]) -> Result<()>;

    /// Retrieves the wrapping of a key for a specific parent.
    fn get_wrapping(&self, parent: &str, id: &str) -> Result<Cow<'_, [u8]>>;

    /// Retrieves the wrappings of a specific parent.
    fn get_wrappings(&self, parent: &str) -> Result<Vec<Cow<'_, [u8]>>>;

    /// Finds the shortest path between two key IDs in the graph.
    fn find_path(&self, src: &str, dest: &str) -> Result<Vec<Cow<'_, [u8]>>>;
}
