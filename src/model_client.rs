use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};

use crate::model_manifest::{parse_manifest, ModelManifest};

#[derive(Clone)]
pub struct ModelApiClient {
    pub base_url: String,
    pub api_key: String,
}

impl ModelApiClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        Self { base_url, api_key }
    }

    pub fn manifest_url(&self) -> String {
        format!("{}/v1/models/manifest", self.base_url.trim_end_matches('/'))
    }

    pub fn artifact_url(&self, artifact_id: &str) -> String {
        format!(
            "{}/v1/models/artifacts/{}",
            self.base_url.trim_end_matches('/'),
            artifact_id
        )
    }

    pub async fn fetch_manifest(&self) -> Result<ModelManifest> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(self.api_key.as_str()).context("invalid api key")?,
        );

        let resp = reqwest::Client::new()
            .get(self.manifest_url())
            .headers(headers)
            .send()
            .await
            .context("manifest request failed")?;

        let status = resp.status();
        let ct = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body = resp.bytes().await.context("failed to read manifest body")?;

        if !status.is_success() {
            anyhow::bail!("manifest request failed with status {}", status);
        }

        parse_manifest(&body, ct.as_deref())
    }
}
