use std::fs::{read_to_string, write};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::{from_str, to_string_pretty};

use super::GraphRepository;
use crate::{KeyGraph, Result};

pub struct JsonLocalRepository(String);

impl JsonLocalRepository {
    pub fn new(path: &str) -> Self {
        Self(path.to_string())
    }
}

impl GraphRepository for JsonLocalRepository {
    fn save<G: KeyGraph + Serialize>(&self, graph: &G) -> Result<()> {
        let json = to_string_pretty(graph)?;
        write(&self.0, json)?;
        Ok(())
    }

    fn load<G: KeyGraph + DeserializeOwned>(&self) -> Result<G> {
        let json = read_to_string(&self.0)?;
        Ok(from_str(&json)?)
    }
}
