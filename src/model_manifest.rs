use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    Onnx,
    Torch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTask {
    AppIdFlow,
    ExfilFlow,
    ExfilSession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArtifact {
    pub id: String,
    pub task: ModelTask,
    pub format: ModelFormat,
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    pub version: String,
    pub created_at_rfc3339: String,
    pub artifacts: Vec<ModelArtifact>,
    pub signature: Option<String>,
}

pub fn parse_manifest(bytes: &[u8], content_type: Option<&str>) -> Result<ModelManifest> {
    let hint = content_type.unwrap_or("").to_ascii_lowercase();

    if hint.contains("yaml") || hint.contains("yml") {
        let m: ModelManifest = serde_yaml::from_slice(bytes).context("invalid yaml manifest")?;
        return Ok(m);
    }

    if hint.contains("json") {
        let m: ModelManifest = serde_json::from_slice(bytes).context("invalid json manifest")?;
        return Ok(m);
    }

    if let Ok(m) = serde_json::from_slice::<ModelManifest>(bytes) {
        return Ok(m);
    }

    let m: ModelManifest = serde_yaml::from_slice(bytes).context("invalid manifest")?;
    Ok(m)
}
