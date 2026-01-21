use anyhow::{Context, Result};
use object_store::{aws::AmazonS3Builder, gcp::GoogleCloudStorageBuilder, ObjectStore};
use std::sync::Arc;
use std::path::Path;
use crate::storage::nfs_check::verify_nfs_mount_options;

#[derive(Debug, Clone, PartialEq)]
pub enum StorageBackend {
    S3,
    GCS,
    Local,
}

impl std::str::FromStr for StorageBackend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "s3" | "oci" | "aws" => Ok(StorageBackend::S3),
            "gcs" | "google" => Ok(StorageBackend::GCS),
            "local" | "file" | "nfs" => Ok(StorageBackend::Local),
            _ => anyhow::bail!("Unknown storage backend: {}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub path: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Local,
            bucket: None,
            region: None,
            endpoint: None,
            access_key: None,
            secret_key: None,
            path: Some("/tmp/captures".to_string()),
        }
    }
}

pub fn create_object_store(config: &StorageConfig) -> Result<Arc<dyn ObjectStore>> {
    match config.backend {
        StorageBackend::S3 => {
            let bucket = config.bucket.as_deref().context("Bucket name required for S3/OCI")?;
            let mut builder = AmazonS3Builder::new()
                .with_bucket_name(bucket);
            
            if let Some(region) = &config.region {
                builder = builder.with_region(region);
            }
            
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint);
                // Allow HTTP for local testing or internal endpoints if needed
                if endpoint.starts_with("http://") {
                    builder = builder.with_allow_http(true);
                }
            }
            
            if let Some(key) = &config.access_key {
                builder = builder.with_access_key_id(key);
            }
            
            if let Some(secret) = &config.secret_key {
                builder = builder.with_secret_access_key(secret);
            }
            
            let store = builder.build().context("Failed to build S3 object store")?;
            Ok(Arc::new(store))
        },
        StorageBackend::GCS => {
            let bucket = config.bucket.as_deref().context("Bucket name required for GCS")?;
            let builder = GoogleCloudStorageBuilder::new()
                .with_bucket_name(bucket);
            
            // GCS auth is typically handled via Google application default credentials (env vars)
            // or service account path. Builder allows customizing but defaults are usually fine.
            
            let store = builder.build().context("Failed to build GCS object store")?;
            Ok(Arc::new(store))
        },
        StorageBackend::Local => {
            let path_str = config.path.as_deref().unwrap_or("/tmp/captures");
            let path = Path::new(path_str);
            
            // Perform NFS validation
            // If the directory doesn't exist, we might create it, but we can't check mount options on non-existent path.
            // Usually we check the parent if the dir doesn't exist yet?
            if path.exists() {
                verify_nfs_mount_options(path).context("NFS validation failed")?;
            } else if let Some(parent) = path.parent() {
                if parent.exists() {
                    verify_nfs_mount_options(parent).context("NFS validation failed on parent directory")?;
                }
            }
            
            // Create directory if it doesn't exist (LocalFileSystem doesn't do it automatically always?)
            std::fs::create_dir_all(path).context("Failed to create storage directory")?;
            
            let store = object_store::local::LocalFileSystem::new_with_prefix(path)?;
            Ok(Arc::new(store))
        }
    }
}
