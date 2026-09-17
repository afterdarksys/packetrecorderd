use serde::{Deserialize, Serialize};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    pub api_version: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub signatures: Vec<PayloadSignature>,
    #[serde(default)]
    pub limits: PluginLimits,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PayloadSignature {
    pub offset: usize,
    pub hex: String,
}

impl PayloadSignature {
    pub fn matches(&self, payload: &[u8]) -> Result<bool> {
        let bytes = self.decoded()?;
        let end = self.offset.checked_add(bytes.len()).context("payload signature offset overflow")?;
        Ok(payload.get(self.offset..end) == Some(bytes.as_slice()))
    }

    pub fn decoded(&self) -> Result<Vec<u8>> {
        hex::decode(&self.hex).context("payload signature must be valid hexadecimal")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct PluginLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_fields: usize,
    pub max_annotations: usize,
    pub timeout_ms: u64,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            max_fields: 256,
            max_annotations: 256,
            timeout_ms: 1000,
        }
    }
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
        let config: PluginsConfig = serde_json::from_str(&content)
            .with_context(|| format!("Invalid plugin manifest: {:?}", path))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::new();
        for plugin in &self.plugins {
            if plugin.api_version != "packetrecorder.plugin/v1" {
                bail!("plugin '{}' uses unsupported API version '{}'", plugin.name, plugin.api_version);
            }
            if plugin.name.trim().is_empty() || plugin.executable.trim().is_empty() {
                bail!("plugin name and executable must not be empty");
            }
            if !names.insert(plugin.name.as_str()) {
                bail!("duplicate plugin name '{}'", plugin.name);
            }
            if (plugin.ports.is_empty() && plugin.signatures.is_empty()) || plugin.ports.contains(&0) {
                bail!("plugin '{}' must select a non-zero port or payload signature", plugin.name);
            }
            for signature in &plugin.signatures {
                signature.matches(&[]).with_context(|| format!("invalid signature for plugin '{}'", plugin.name))?;
            }
            let limits = &plugin.limits;
            if limits.max_request_bytes == 0 || limits.max_response_bytes == 0
                || limits.max_request_bytes > 16 * 1024 * 1024
                || limits.max_response_bytes > 16 * 1024 * 1024
                || limits.max_fields == 0 || limits.max_fields > 4096
                || limits.max_annotations == 0 || limits.max_annotations > 4096
                || limits.timeout_ms == 0 || limits.timeout_ms > 30_000
            {
                bail!("plugin '{}' has invalid resource limits", plugin.name);
            }
        }
        Ok(())
    }

    pub fn empty() -> Self {
        Self { plugins: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str) -> String {
        format!(r#"{{"plugins":[{{"name":"demo","api_version":"{}","executable":"python3","args":["plugin.py"],"ports":[9999]}}]}}"#, version)
    }

    #[test]
    fn parses_safe_process_manifest() {
        let config: PluginsConfig = serde_json::from_str(&manifest("packetrecorder.plugin/v1")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.plugins[0].args, vec!["plugin.py"]);
        assert_eq!(config.plugins[0].limits.max_response_bytes, 1024 * 1024);
    }

    #[test]
    fn rejects_unknown_api_version_and_empty_selector() {
        let config: PluginsConfig = serde_json::from_str(&manifest("v99")).unwrap();
        assert!(config.validate().is_err());
        let mut config: PluginsConfig = serde_json::from_str(&manifest("packetrecorder.plugin/v1")).unwrap();
        config.plugins[0].ports.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn payload_signature_matches_at_declared_offset() {
        let signature = PayloadSignature { offset: 2, hex: "41434d45".to_string() };
        assert!(signature.matches(b"xxACME-data").unwrap());
        assert!(!signature.matches(b"xxNOPE-data").unwrap());
        assert!(PayloadSignature { offset: 0, hex: "xyz".to_string() }.matches(b"x").is_err());
    }
}
