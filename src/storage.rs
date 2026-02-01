mod json;

use crate::{EncryptorError, core::Result};
pub use json::JsonStorage;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait KeyStorage {
    fn load(&self) -> Result<KeyGraph>;
    fn save(&self, keys: &KeyGraph) -> Result<()>;
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct KeyNode {
    algo: String,
    wrappings: HashMap<String, Vec<u8>>,
}

impl KeyNode {
    fn new(algo: &str) -> Self {
        Self {
            algo: algo.to_string(),
            wrappings: HashMap::new(),
        }
    }

    fn add_wrapping(&mut self, label: &str, wrapping: &[u8]) -> Option<Vec<u8>> {
        self.wrappings.insert(label.to_string(), wrapping.into())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

    pub fn add_wrapping(
        &mut self,
        id: &str,
        algorithm: &str,
        parent: &str,
        data: &[u8],
    ) -> Result<()> {
        if !self.has_root_or_node(parent) {
            return Err(EncryptorError::InvalidParentKeyID(parent.to_string()));
        }

        if !self.has_node(id) {
            let new_node = KeyNode::new(algorithm);
            self.nodes.insert(id.into(), new_node);
        }

        let node = self.nodes.get_mut(id).ok_or(EncryptorError::TBD)?;
        node.add_wrapping(parent, data);
        Ok(())
    }

    pub fn get_wrapping(&self, id: &str, parent: &str) -> Option<&Vec<u8>> {
        self.nodes.get(id)?.wrappings.get(&parent.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const ALGO: &'static str = "aes_gcm";
    pub(crate) const KEK_LABEL: &'static str = "kek";
    pub(crate) const MASTER_LABEL: &'static str = "master";
    pub(crate) const RECOVERY_LABEL: &'static str = "recovery";

    pub(crate) const MASTER_KEY: [u8; 60] = [
        69, 4, 131, 16, 243, 114, 55, 50, 143, 173, 62, 57, 1, 229, 144, 128, 129, 175, 17, 231, 1,
        255, 154, 150, 142, 17, 185, 157, 246, 54, 238, 232, 106, 208, 172, 93, 101, 129, 118, 89,
        214, 52, 65, 46, 125, 27, 124, 78, 87, 213, 49, 77, 21, 212, 98, 123, 164, 102, 21, 185,
    ];
    pub(crate) const RECOVERY_KEY: [u8; 60] = [
        113, 94, 4, 21, 212, 215, 60, 86, 124, 33, 224, 244, 41, 8, 63, 99, 159, 79, 62, 168, 103,
        43, 90, 189, 165, 44, 225, 170, 159, 175, 229, 65, 95, 177, 249, 29, 137, 123, 38, 224,
        189, 84, 143, 73, 156, 126, 42, 147, 25, 204, 53, 112, 107, 102, 91, 246, 131, 162, 139,
        151,
    ];

    #[test]
    fn test_add_node() {
        let mut graph = KeyGraph::new();

        graph
            .add_root(KEK_LABEL)
            .expect("Unable to add KEK as root");
        graph
            .add_wrapping(MASTER_LABEL, ALGO, KEK_LABEL, &MASTER_KEY)
            .expect("Failed to add wrapping for master key encrypted with kek");
        graph
            .add_wrapping(RECOVERY_LABEL, ALGO, MASTER_LABEL, &RECOVERY_KEY)
            .expect("Failed to add wrapping for recovery key encrypted with master key");

        assert_eq!(sample_graph(), graph);
    }

    pub(crate) fn sample_graph() -> KeyGraph {
        KeyGraph {
            version: CURRENT_VERSION.to_string(),
            roots: vec![KEK_LABEL.to_string()],
            nodes: HashMap::from([
                (
                    MASTER_LABEL.to_string(),
                    KeyNode {
                        algo: ALGO.to_string(),
                        wrappings: HashMap::from([(KEK_LABEL.to_string(), MASTER_KEY.to_vec())]),
                    },
                ),
                (
                    RECOVERY_LABEL.to_string(),
                    KeyNode {
                        algo: ALGO.to_string(),
                        wrappings: HashMap::from([(
                            MASTER_LABEL.to_string(),
                            RECOVERY_KEY.to_vec(),
                        )]),
                    },
                ),
            ]),
        }
    }
}
