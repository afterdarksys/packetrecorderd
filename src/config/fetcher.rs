use anyhow::{Context, Result};
use curl::easy::Easy;
use std::io::Write;

pub struct ConfigFetcher;

impl ConfigFetcher {
    /// Fetch configuration or data from a URL using curl
    pub fn fetch_url(url: &str) -> Result<Vec<u8>> {
        let mut dst = Vec::new();
        let mut easy = Easy::new();
        easy.url(url).context("Failed to set URL")?;
        
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|data| {
                dst.write_all(data).unwrap();
                Ok(data.len())
            })?;
            transfer.perform().context("Failed to perform curl request")?;
        }
        
        Ok(dst)
    }
}
