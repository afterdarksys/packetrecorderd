use anyhow::{Result, Context};
use std::process::{Command, Stdio, Child};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::{Write, Read};
use tracing::{info, warn};
use prost::Message;

// Include the generated proto modules
pub mod plugin_proto {
    tonic::include_proto!("packetrecorder.v1");
}

use plugin_proto::{PluginParseRequest, PluginParseResponse};

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub attributes: HashMap<String, String>,
}

pub struct PluginManager {
    plugins: HashMap<u16, Arc<Mutex<PluginInstance>>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn register_plugin(&mut self, name: String, command: String, port: u16) -> Result<()> {
        info!("Registering plugin '{}' for port {}", name, port);
        let instance = PluginInstance::new(name, command)?;
        self.plugins.insert(port, Arc::new(Mutex::new(instance)));
        Ok(())
    }

    pub fn get_plugin(&self, port: u16) -> Option<Arc<Mutex<PluginInstance>>> {
        self.plugins.get(&port).cloned()
    }
}

pub struct PluginInstance {
    name: String,
    command: String,
    child: Option<Child>,
}

impl PluginInstance {
    pub fn new(name: String, command: String) -> Result<Self> {
        let mut instance = Self {
            name,
            command,
            child: None,
        };
        instance.start_process()?;
        Ok(instance)
    }

    fn start_process(&mut self) -> Result<()> {
        info!("Starting plugin process: {}", self.command);
        let mut parts = self.command.split_whitespace();
        let cmd = parts.next().ok_or_else(|| anyhow::anyhow!("Invalid command"))?;
        let args: Vec<&str> = parts.collect();

        let child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context(format!("Failed to spawn plugin command: {}", self.command))?;

        self.child = Some(child);
        Ok(())
    }

    pub fn parse(&mut self, request: PluginParseRequest) -> Result<PluginParseResponse> {
        for attempt in 0..2 {
            if self.child.is_none() {
                self.start_process()?;
            }

            match self.try_parse_internal(&request) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if attempt == 0 {
                        warn!("Plugin {} failed (attempt {}): {:?}, retrying...", self.name, attempt + 1, e);
                        self.child = None; // Mark for restart
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(anyhow::anyhow!("Plugin failed after retries"))
    }

    fn try_parse_internal(&mut self, request: &PluginParseRequest) -> Result<PluginParseResponse> {
        let child = self.child.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin process not running"))?;
        let stdin = child.stdin.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin stdin not captured"))?;
        let stdout = child.stdout.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin stdout not captured"))?;

        // Write length-prefixed protobuf
        let mut buf = Vec::new();
        request.encode(&mut buf)?;
        let len = buf.len() as u32;
        stdin.write_all(&len.to_be_bytes())?;
        stdin.write_all(&buf)?;
        stdin.flush()?;

        // Read length-prefixed response
        let mut len_buf = [0u8; 4];
        stdout.read_exact(&mut len_buf)?;
        
        let response_len = u32::from_be_bytes(len_buf) as usize;
        let mut response_buf = vec![0u8; response_len];
        stdout.read_exact(&mut response_buf)?;

        let response = PluginParseResponse::decode(&response_buf[..])?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_plugin_communication() {
        // Find the example plugin
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("examples/plugins/example_plugin.py");
        let plugin_path = d.to_string_lossy().to_string();

        let command = format!("python3 {}", plugin_path);
        
        // Skip if python3 or the script is not available (CI/CD safety)
        if Command::new("python3").arg("--version").output().is_err() {
            return;
        }

        let mut instance = PluginInstance::new("test_plugin".to_string(), command).expect("Failed to create plugin instance");

        let req = PluginParseRequest {
            payload: b"Hello Plugin".to_vec(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1234,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 80,
            protocol: "TCP".to_string(),
        };

        let resp = instance.parse(req).expect("Failed to parse");
        
        assert!(resp.success);
        assert_eq!(resp.name, "ExamplePlugin");
        assert_eq!(resp.attributes.get("payload_string").map(|s| s.as_str()), Some("Hello Plugin"));
        assert_eq!(resp.attributes.get("src").map(|s| s.as_str()), Some("127.0.0.1:1234"));
    }
}
