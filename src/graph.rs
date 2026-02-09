use crate::{EncryptorError, Result};

use std::collections::{HashMap, HashSet, VecDeque};

#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, PartialEq, Eq)]
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

#[cfg_attr(feature = "json", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, PartialEq, Eq)]
pub struct KeyGraph {
    version: String,
    roots: Vec<String>,
    nodes: HashMap<String, KeyNode>,
}

const CURRENT_VERSION: &'static str = "0.1";

impl KeyGraph {
    pub fn new() -> Self {
        Self {
            version: CURRENT_VERSION.into(),
            roots: vec![],
            nodes: HashMap::new(),
        }
    }

    pub fn has_root(&self, id: &str) -> bool {
        self.roots.contains(&id.to_string())
    }

    fn has_node(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    fn has_root_or_node(&self, id: &str) -> bool {
        self.has_root(id) || self.has_node(id)
    }

    pub fn add_root(&mut self, id: &str) -> Result<()> {
        self.roots.push(id.to_string());
        Ok(())
    }

    pub fn add_wrapping(&mut self, id: &str, parent: &str, data: &[u8]) -> Result<()> {
        if !self.has_root_or_node(parent) {
            return Err(EncryptorError::InvalidParentKeyID(parent.to_string()));
        }

        if !self.has_node(id) {
            let new_node = KeyNode::new();
            self.nodes.insert(id.into(), new_node);
        }

        let node = self
            .nodes
            .get_mut(id)
            .ok_or(EncryptorError::InvalidKeyID(id.to_string()))?;
        node.add_wrapping(parent, data);
        Ok(())
    }

    pub fn get_wrapping(&self, id: &str, parent: &str) -> Option<&Vec<u8>> {
        self.nodes.get(id)?.wrappings.get(&parent.to_string())
    }

    pub fn find_shortest_path(&self, src: &str, dest: &str) -> Option<Vec<String>> {
        let src = src.to_string();
        let dest = dest.to_string();

        if src == dest {
            return Some(vec![src]);
        }

        if !self.has_root_or_node(&src) || !self.has_root_or_node(&dest) {
            return None;
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
}
