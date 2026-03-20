use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    pub command: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginsConfig {
    pub plugins: Vec<PluginConfig>,
}

impl PluginsConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = fs::metadata(path)?;
                let mode = metadata.mode();
                if (mode & 0o022) != 0 {
                    tracing::warn!("SECURITY WARNING: {:?} has insecure permissions (mode {:o}). It should be 0600 (owner read/write only) to prevent command injection.", path, mode & 0o777);
                }
            }
        }

        let content = fs::read_to_string(path)?;
        let config: PluginsConfig = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn empty() -> Self {
        Self { plugins: Vec::new() }
    }
}
