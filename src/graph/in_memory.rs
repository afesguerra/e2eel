use crate::{Error, Result};
use super::KeyGraph;

use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
struct KeyNode {
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
#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InMemoryKeyGraph {
    version: String,
    roots: Vec<String>,
    nodes: HashMap<String, KeyNode>,
}

const CURRENT_VERSION: &str = "0.1";

impl InMemoryKeyGraph {
    /// Creates a new empty in-memory key graph.
    pub fn new() -> Self {
        Self {
            version: CURRENT_VERSION.into(),
            roots: vec![],
            nodes: HashMap::new(),
        }
    }

    fn has_node(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    fn has_root_or_node(&self, id: &str) -> bool {
        self.has_root(id) || self.has_node(id)
    }

    /// Loads a key graph from a JSON file.
    #[cfg(feature = "json")]
    pub fn load_from_json(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Saves the key graph to a JSON file.
    #[cfg(feature = "json")]
    pub fn save_to_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

impl KeyGraph for InMemoryKeyGraph {
    fn has_root(&self, id: &str) -> bool {
        self.roots.contains(&id.to_string())
    }

    fn add_root(&mut self, id: &str) -> Result<()> {
        self.roots.push(id.to_string());
        Ok(())
    }

    fn add_wrapping(&mut self, id: &str, parent: &str, data: &[u8]) -> Result<()> {
        if !self.has_root_or_node(parent) {
            return Err(Error::InvalidParentKeyID(parent.to_string()));
        }

        if !self.has_node(id) {
            let new_node = KeyNode::new();
            self.nodes.insert(id.into(), new_node);
        }

        let node = self
            .nodes
            .get_mut(id)
            .ok_or(Error::InvalidKeyID(id.to_string()))?;
        node.add_wrapping(parent, data);
        Ok(())
    }

    fn get_wrapping(&self, id: &str, parent: &str) -> Option<&Vec<u8>> {
        self.nodes.get(id)?.wrappings.get(&parent.to_string())
    }

    fn find_shortest_path(&self, src: &str, dest: &str) -> Option<Vec<String>> {
        let src = src.to_string();
        let dest = dest.to_string();

        if !self.has_root_or_node(&src) || !self.has_root_or_node(&dest) {
            return None;
        }

        if src == dest {
            return Some(vec![src]);
        }

        // Lazy reverse BFS: dest -> ... -> src (no full adj build)
        let mut queue = VecDeque::new();
        queue.push_back(dest.clone());

        let mut visited = HashSet::new();
        visited.insert(dest.clone());

        let mut parent: HashMap<String, String> = HashMap::new();

        while let Some(curr) = queue.pop_front() {
            if curr == src {
                // Reconstruct: src <- ... <- dest → reverse to src -> dest
                let mut path = vec![src.clone()];
                let mut at = src;
                while at != dest {
                    at = parent.get(&at).cloned()?;
                    path.push(at.clone());
                }
                return Some(path);
            }

            // Forward neighbors: parents of curr (direct from its wrappings keys)
            if let Some(node) = self.nodes.get(&curr) {
                for parent_id in node.wrappings.keys() {
                    let p = parent_id.as_str();
                    if !visited.contains(p) {
                        visited.insert(p.to_string());
                        parent.insert(p.to_string(), curr.clone());
                        queue.push_back(p.to_string());
                    }
                }
            }
        }
        None
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
        graph.add_wrapping(MASTER_LABEL, KEK_LABEL, &MASTER_KEY).unwrap();
        graph.add_wrapping(RECOVERY_LABEL, MASTER_LABEL, &RECOVERY_KEY).unwrap();
        graph
    }

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

    #[test]
    fn test_path_nonexistent_src() {
        let graph = sample_graph();
        assert!(graph.find_shortest_path("ghost", RECOVERY_LABEL).is_none());
    }

    #[test]
    fn test_path_nonexistent_dest() {
        let graph = sample_graph();
        assert!(graph.find_shortest_path(KEK_LABEL, "ghost").is_none());
    }

    #[test]
    fn test_path_both_nonexistent() {
        let graph = sample_graph();
        assert!(graph.find_shortest_path("ghost_src", "ghost_dest").is_none());
    }

    #[test]
    fn test_path_same_root() {
        let graph = sample_graph();
        assert_eq!(
            graph.find_shortest_path(KEK_LABEL, KEK_LABEL),
            Some(vec![KEK_LABEL.to_string()])
        );
    }

    #[test]
    fn test_path_same_node() {
        let graph = sample_graph();
        assert_eq!(
            graph.find_shortest_path(RECOVERY_LABEL, RECOVERY_LABEL),
            Some(vec![RECOVERY_LABEL.to_string()])
        );
    }

    #[test]
    fn test_path_direct_adjacent() {
        let graph = sample_graph();
        assert_eq!(
            graph.find_shortest_path(KEK_LABEL, MASTER_LABEL),
            Some(vec![KEK_LABEL.to_string(), MASTER_LABEL.to_string()])
        );
    }

    #[test]
    fn test_path_same_nonexistent_node() {
        // src == dest but neither exists — existence check must fire before the same-node shortcut
        let graph = sample_graph();
        assert!(graph.find_shortest_path("ghost", "ghost").is_none());
    }

    #[test]
    fn test_path_no_connection() {
        // Two completely disconnected subtrees: rootA -> nodeA, rootB -> nodeB
        let mock_data = [0u8; 1];
        let mut graph = InMemoryKeyGraph::new();

        graph.add_root("rootA").unwrap();
        graph.add_wrapping("nodeA", "rootA", &mock_data).unwrap();

        graph.add_root("rootB").unwrap();
        graph.add_wrapping("nodeB", "rootB", &mock_data).unwrap();

        assert!(graph.find_shortest_path("rootA", "nodeB").is_none());
    }

    // --- add_wrapping edge cases ---

    #[test]
    fn test_add_wrapping_unknown_parent() {
        let mut graph = InMemoryKeyGraph::new();
        let result = graph.add_wrapping("child", "nonexistent_parent", &[0u8; 1]);
        assert!(matches!(result, Err(Error::InvalidParentKeyID(_))));
    }

    // --- get_wrapping edge cases ---

    #[test]
    fn test_get_wrapping_returns_data() {
        let mut graph = InMemoryKeyGraph::new();
        let data = vec![1u8, 2, 3, 4];
        graph.add_root("root").unwrap();
        graph.add_wrapping("child", "root", &data).unwrap();
        assert_eq!(graph.get_wrapping("child", "root"), Some(&data));
    }

    #[test]
    fn test_get_wrapping_unknown_node() {
        let graph = sample_graph();
        assert!(graph.get_wrapping("ghost", KEK_LABEL).is_none());
    }

    #[test]
    fn test_get_wrapping_unknown_parent() {
        let graph = sample_graph();
        // MASTER_LABEL is a valid node but "ghost_parent" is not its parent
        assert!(graph.get_wrapping(MASTER_LABEL, "ghost_parent").is_none());
    }

    #[test]
    #[cfg(feature = "json")]
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
