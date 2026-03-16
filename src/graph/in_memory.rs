use crate::{Error, Result};
use super::KeyGraph;

use std::collections::{HashMap, HashSet, VecDeque};
use std::borrow::Cow;
use std::option::Option;

#[serde_with::serde_as]
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
struct KeyNode {
    #[serde_as(as = "HashMap<_, serde_with::base64::Base64>")]
    wrappings: HashMap<String, Vec<u8>>,
}

impl KeyNode {
    fn new() -> Self {
        Self {
            wrappings: HashMap::new(),
        }
    }

    fn add_wrapping(&mut self, label: &str, wrapping: &[u8]) -> Option<Vec<u8>> {
        self.wrappings.insert(label.to_string(), wrapping.into())
    }
}

/// In-memory implementation of the KeyGraph trait.
/// Stores the key graph structure and all wrappings in memory using HashMaps.
#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct InMemoryKeyGraph {
    version: String,
    roots: HashSet<String>,
    nodes: HashMap<String, KeyNode>,
}

const CURRENT_VERSION: &str = "0.1";

impl InMemoryKeyGraph {
    /// Creates a new empty in-memory key graph.
    pub fn new() -> Self {
        Self {
            version: CURRENT_VERSION.into(),
            roots: HashSet::new(),
            nodes: HashMap::new(),
        }
    }

    fn has_root_or_node(&self, id: &str) -> bool {
        self.roots.contains(id) || self.nodes.contains_key(id)
    }

    /// Loads a key graph from a JSON file.
    pub fn load_from_json(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Saves the key graph to a JSON file.
    pub fn save_to_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl KeyGraph for InMemoryKeyGraph {
    fn add_root(&mut self, id: &str) -> Result<()> {
        if self.has_root_or_node(id) {
            return Err(Error::DuplicateKeyID(id.to_string()));
        }

        self.roots.insert(id.to_string());
        Ok(())
    }

    fn add_wrapping(&mut self, parent: &str, id: &str, data: &[u8]) -> Result<()> {
        if !self.has_root_or_node(parent) {
            return Err(Error::InvalidParentKeyID(parent.to_string()));
        }

        if !self.nodes.contains_key(id) {
            let new_node = KeyNode::new();
            self.nodes.insert(id.into(), new_node);
        }

        let node = self
            .nodes
            .get_mut(id)
            .ok_or_else(|| Error::InvalidKeyID(id.to_string()))?;
        node.add_wrapping(parent, data);
        Ok(())
    }

    fn get_wrapping(&self, parent: &str, id: &str) -> Option<Cow<'_, [u8]>> {
        self
            .nodes
            .get(id)?
            .wrappings
            .get(parent)
            .map(Cow::from)
    }

    fn get_wrappings(&self, parent: &str) -> Vec<Cow<'_, [u8]>> {
        self
            .nodes
            .values()
            .filter_map(|f| f.wrappings.get(parent))
            .map(Cow::from)
            .collect()
    }

    fn find_path(&self, src: &str, dest: &str) -> Result<Vec<Cow<'_, [u8]>>> {
        if !self.has_root_or_node(src) {
            return Err(Error::InvalidKeyID(src.to_string()));
        }

        if !self.has_root_or_node(dest) {
            return Err(Error::InvalidKeyID(dest.to_string()));
        }

        if src == dest {
            return Ok(vec![]);
        }

        // Lazy reverse BFS: dest -> ... -> src (no full adj build)
        let mut queue = VecDeque::<&str>::new();
        queue.push_back(dest);

        let mut visited = HashSet::<&str>::new();
        visited.insert(dest);

        let mut parent: HashMap<&str, &str> = HashMap::new();

        while let Some(curr) = queue.pop_front() {
            if curr == src {
                // Reconstruct: src <- ... <- dest → reverse to src -> dest
                let mut path = vec![];
                let mut at = src;
                let mut old_parent: &str;
                while at != dest {
                    old_parent = at;
                    at = parent.get(at).ok_or(Error::CorruptedGraph)?;
                    path.push(self.get_wrapping(old_parent, at).ok_or(Error::CorruptedGraph)?);
                }
                return Ok(path);
            }

            // Forward neighbors: parents of curr (direct from its wrappings keys)
            if let Some(node) = self.nodes.get(curr) {
                for parent_id in node.wrappings.keys() {
                    let p = parent_id.as_str();
                    if !visited.contains(p) {
                        visited.insert(p);
                        parent.insert(p, curr);
                        queue.push_back(p);
                    }
                }
            }
        }
        Err(Error::NoSuchPath(format!("No path found from {} to {}", src, dest)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_data::{KEK_LABEL, MASTER_LABEL, RECOVERY_LABEL};

    const MASTER_KEY: [u8; 60] = [
        69, 4, 131, 16, 243, 114, 55, 50, 143, 173, 62, 57, 1, 229, 144, 128, 129, 175, 17, 231, 1,
        255, 154, 150, 142, 17, 185, 157, 246, 54, 238, 232, 106, 208, 172, 93, 101, 129, 118, 89, 214,
        52, 65, 46, 125, 27, 124, 78, 87, 213, 49, 77, 21, 212, 98, 123, 164, 102, 21, 185,
    ];

    const RECOVERY_KEY: [u8; 60] = [
        113, 94, 4, 21, 212, 215, 60, 86, 124, 33, 224, 244, 41, 8, 63, 99, 159, 79, 62, 168, 103, 43,
        90, 189, 165, 44, 225, 170, 159, 175, 229, 65, 95, 177, 249, 29, 137, 123, 38, 224, 189, 84,
        143, 73, 156, 126, 42, 147, 25, 204, 53, 112, 107, 102, 91, 246, 131, 162, 139, 151,
    ];

    fn sample_graph() -> InMemoryKeyGraph {
        let mut graph = InMemoryKeyGraph::new();
        graph.add_root(KEK_LABEL).unwrap();
        graph.add_wrapping(KEK_LABEL, MASTER_LABEL, &MASTER_KEY).unwrap();
        graph.add_wrapping(MASTER_LABEL, RECOVERY_LABEL, &RECOVERY_KEY).unwrap();
        graph
    }

    #[test]
    fn test_shortest_path() {
        let graph = sample_graph();

        let shortest_path = graph
            .find_path(KEK_LABEL, RECOVERY_LABEL)
            .expect("Cannot find path between KEK and RECOVERY");

        assert_eq!(
            shortest_path,
            vec![Cow::from(&MASTER_KEY), Cow::from(&RECOVERY_KEY)]
        );
    }

    #[test]
    fn test_multiple_paths() {
        let mock_data = [0u8; 1];
        let mut graph = InMemoryKeyGraph::new();

        graph.add_root("root").unwrap();
        graph.add_wrapping("root", "nodeA1", &mock_data).unwrap();
        graph.add_wrapping("root", "nodeB1", &mock_data).unwrap();

        graph.add_wrapping("nodeA1", "nodeA2", &mock_data).unwrap();
        graph.add_wrapping("nodeA2", "nodeC", &mock_data).unwrap();
        graph.add_wrapping("nodeB1", "nodeC", &mock_data).unwrap();

        assert_eq!(
            vec![Cow::from(&mock_data), Cow::from(&mock_data)],
            graph.find_path("root", "nodeC").unwrap()
        )
    }

    #[test]
    fn test_path_nonexistent_src() {
        let graph = sample_graph();
        assert!(graph.find_path("ghost", RECOVERY_LABEL).is_err());
    }

    #[test]
    fn test_path_nonexistent_dest() {
        let graph = sample_graph();
        assert!(graph.find_path(KEK_LABEL, "ghost").is_err());
    }

    #[test]
    fn test_path_both_nonexistent() {
        let graph = sample_graph();
        assert!(graph.find_path("ghost_src", "ghost_dest").is_err());
    }

    #[test]
    fn test_path_same_root() {
        let graph = sample_graph();
        let result = graph.find_path(KEK_LABEL, KEK_LABEL);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_path_same_node() {
        let graph = sample_graph();
        let result = graph.find_path(RECOVERY_LABEL, RECOVERY_LABEL);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_path_direct_adjacent() {
        let graph = sample_graph();
        assert_eq!(
            graph.find_path(KEK_LABEL, MASTER_LABEL).unwrap(),
            vec![Cow::from(&MASTER_KEY)]
        );
    }

    #[test]
    fn test_path_same_nonexistent_node() {
        // src == dest but neither exists — existence check must fire before the same-node shortcut
        let graph = sample_graph();
        assert!(graph.find_path("ghost", "ghost").is_err());
    }

    #[test]
    fn test_path_no_connection() {
        // Two completely disconnected subtrees: rootA -> nodeA, rootB -> nodeB
        let mock_data = [0u8; 1];
        let mut graph = InMemoryKeyGraph::new();

        graph.add_root("rootA").unwrap();
        graph.add_wrapping("rootA", "nodeA", &mock_data).unwrap();

        graph.add_root("rootB").unwrap();
        graph.add_wrapping("rootB", "nodeB", &mock_data).unwrap();

        assert!(graph.find_path("rootA", "nodeB").is_err());
    }

    // --- add_wrapping edge cases ---

    #[test]
    fn test_add_wrapping_unknown_parent() {
        let mut graph = InMemoryKeyGraph::new();
        let result = graph.add_wrapping("nonexistent_parent", "child", &[0u8; 1]);
        assert!(matches!(result, Err(Error::InvalidParentKeyID(_))));
    }

    // --- get_wrapping edge cases ---

    #[test]
    fn test_get_wrapping_returns_data() {
        let mut graph = InMemoryKeyGraph::new();
        let data = vec![1u8, 2, 3, 4];
        graph.add_root("root").unwrap();
        graph.add_wrapping("root", "child", &data).unwrap();
        assert_eq!(graph.get_wrapping("root", "child"), Some(Cow::from(&data)));
    }

    #[test]
    fn test_get_wrapping_unknown_node() {
        let graph = sample_graph();
        assert!(graph.get_wrapping(KEK_LABEL, "ghost").is_none());
    }

    #[test]
    fn test_get_wrapping_unknown_parent() {
        let graph = sample_graph();
        // MASTER_LABEL is a valid node but "ghost_parent" is not its parent
        assert!(graph.get_wrapping("ghost_parent", MASTER_LABEL).is_none());
    }

    #[test]
    fn test_get_wrappings() {
        let graph = sample_graph();
        let wrappings = graph.get_wrappings(KEK_LABEL);
        assert_eq!(wrappings.len(), 1);
        assert_eq!(wrappings[0], Cow::from(&MASTER_KEY));
    }

    #[test]
    fn test_json_serialization() {
        use std::fs::{create_dir_all, metadata, remove_file};

        const JSON_PATH: &str = "tmp/serde.json";

        // Clean up any existing file
        let _ = remove_file(JSON_PATH);
        create_dir_all("tmp").expect("Unable to create tmp dir");

        let graph = sample_graph();

        // Test save
        graph.save_to_json(JSON_PATH).expect("Error saving graph");

        // Verify file exists
        assert!(metadata(JSON_PATH).is_ok());

        // Test load
        let loaded = InMemoryKeyGraph::load_from_json(JSON_PATH)
            .expect("Unable to load graph");
        assert_eq!(loaded, graph);

        // Clean up
        let _ = remove_file(JSON_PATH);
    }
}
