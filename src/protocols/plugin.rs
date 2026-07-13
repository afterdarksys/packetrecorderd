use anyhow::{Result, Context};
use std::process::{Command, Stdio, Child};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::Read;
#[cfg(not(unix))]
use std::io::Write;
use tracing::{info, warn};
use prost::Message;
use crate::config::plugins::{PluginConfig, PluginLimits};

// Include the generated proto modules
pub mod plugin_proto {
    tonic::include_proto!("packetrecorder.v1");
}

use plugin_proto::{PluginParseRequest, PluginParseResponse};

struct CircuitBreaker {
    failures: u32,
    threshold: u32,
    cooldown: std::time::Duration,
    opened_at: Option<std::time::Instant>,
}

impl CircuitBreaker {
    fn new(threshold: u32, cooldown: std::time::Duration) -> Self {
        Self { failures: 0, threshold, cooldown, opened_at: None }
    }
    fn allow(&mut self) -> bool {
        match self.opened_at {
            Some(opened) if opened.elapsed() < self.cooldown => false,
            Some(_) => { self.opened_at = None; self.failures = 0; true }
            None => true,
        }
    }
    fn failure(&mut self) {
        self.failures += 1;
        if self.failures >= self.threshold { self.opened_at = Some(std::time::Instant::now()); }
    }
    fn success(&mut self) { self.failures = 0; self.opened_at = None; }
    fn consecutive_failures(&self) -> u32 { self.failures }
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub attributes: HashMap<String, String>,
    pub summary: String,
    pub confidence: f32,
    pub fields: Vec<plugin_proto::TypedField>,
    pub annotations: Vec<plugin_proto::ByteAnnotation>,
    pub findings: Vec<plugin_proto::Finding>,
}

#[derive(Clone)]
pub struct PluginManager {
    plugins: HashMap<u16, Arc<Mutex<PluginInstance>>>,
    signatures: Vec<(usize, Vec<u8>, Arc<Mutex<PluginInstance>>)>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            signatures: Vec::new(),
        }
    }

    pub fn register_config(&mut self, config: PluginConfig) -> Result<()> {
        info!("Registering plugin '{}'", config.name);
        let instance = Arc::new(Mutex::new(PluginInstance::new(
            config.name, config.executable, config.args, config.limits,
        )?));
        for port in config.ports { self.plugins.insert(port, Arc::clone(&instance)); }
        for signature in config.signatures {
            self.signatures.push((signature.offset, signature.decoded()?, Arc::clone(&instance)));
        }
        Ok(())
    }

    pub fn match_plugin(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> Option<Arc<Mutex<PluginInstance>>> {
        self.get_plugin(src_port).or_else(|| self.get_plugin(dst_port)).or_else(|| {
            self.signatures.iter().find_map(|(offset, signature, plugin)| {
                let end = offset.checked_add(signature.len())?;
                (payload.get(*offset..end) == Some(signature.as_slice())).then(|| Arc::clone(plugin))
            })
        })
    }

    pub fn register_plugin(&mut self, name: String, executable: String, args: Vec<String>, limits: PluginLimits, port: u16) -> Result<()> {
        info!("Registering plugin '{}' for port {}", name, port);
        let instance = PluginInstance::new(name, executable, args, limits)?;
        self.plugins.insert(port, Arc::new(Mutex::new(instance)));
        Ok(())
    }

    pub fn get_plugin(&self, port: u16) -> Option<Arc<Mutex<PluginInstance>>> {
        self.plugins.get(&port).cloned()
    }
}

pub struct PluginInstance {
    name: String,
    executable: String,
    args: Vec<String>,
    limits: PluginLimits,
    child: Option<Child>,
    circuit: CircuitBreaker,
}

impl PluginInstance {
    pub fn new(name: String, executable: String, args: Vec<String>, limits: PluginLimits) -> Result<Self> {
        let mut instance = Self {
            name,
            executable,
            args,
            limits,
            child: None,
            circuit: CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        };
        instance.start_process()?;
        Ok(instance)
    }

    fn start_process(&mut self) -> Result<()> {
        info!("Starting plugin process: {}", self.executable);
        let mut command = Command::new(&self.executable);
        command.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        let child = command
            .spawn()
            .with_context(|| format!("Failed to spawn plugin executable: {}", self.executable))?;

        self.child = Some(child);
        Ok(())
    }

    pub fn parse(&mut self, request: PluginParseRequest) -> Result<PluginParseResponse> {
        let started = std::time::Instant::now();
        if !self.circuit.allow() {
            crate::metrics::PLUGIN_INVOCATIONS.with_label_values(&[&self.name, "circuit_open"]).inc();
            anyhow::bail!("plugin circuit breaker is open");
        }
        for attempt in 0..2 {
            if self.child.is_none() {
                self.start_process()?;
            }

            match self.try_parse_internal(&request) {
                Ok(response) => {
                    self.circuit.success();
                    crate::metrics::PLUGIN_INVOCATIONS.with_label_values(&[&self.name, "success"]).inc();
                    crate::metrics::PLUGIN_LATENCY.with_label_values(&[&self.name]).observe(started.elapsed().as_secs_f64());
                    return Ok(response);
                },
                Err(e) => {
                    self.stop_process();
                    if attempt == 0 {
                        warn!("Plugin {} failed (attempt {}): {:?}, retrying...", self.name, attempt + 1, e);
                        continue;
                    }
                    self.circuit.failure();
                    crate::metrics::PLUGIN_INVOCATIONS.with_label_values(&[&self.name, "failure"]).inc();
                    crate::metrics::PLUGIN_LATENCY.with_label_values(&[&self.name]).observe(started.elapsed().as_secs_f64());
                    return Err(e);
                }
            }
        }
        Err(anyhow::anyhow!("Plugin failed after retries"))
    }

    fn try_parse_internal(&mut self, request: &PluginParseRequest) -> Result<PluginParseResponse> {
        if request.encoded_len() > self.limits.max_request_bytes {
            anyhow::bail!("plugin request exceeds configured limit");
        }
        let child = self.child.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin process not running"))?;
        let stdin = child.stdin.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin stdin not captured"))?;
        let stdout = child.stdout.as_mut().ok_or_else(|| anyhow::anyhow!("Plugin stdout not captured"))?;

        // Write length-prefixed protobuf
        let mut buf = Vec::new();
        request.encode(&mut buf)?;
        let len = buf.len() as u32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.limits.timeout_ms);
        let mut framed = Vec::with_capacity(4 + buf.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&buf);
        write_all_with_deadline(stdin, &framed, deadline)?;

        // Read length-prefixed response
        let mut len_buf = [0u8; 4];
        read_exact_with_deadline(stdout, &mut len_buf, deadline)?;
        
        let response_len = u32::from_be_bytes(len_buf) as usize;
        if response_len > self.limits.max_response_bytes {
            anyhow::bail!("plugin response exceeds configured limit");
        }
        let mut response_buf = vec![0u8; response_len];
        read_exact_with_deadline(stdout, &mut response_buf, deadline)?;

        let mut response = PluginParseResponse::decode(&response_buf[..])?;
        response.annotations.retain(|annotation| annotation.length != 0);
        self.validate_response(&response, request.payload.len())?;
        Ok(response)
    }

    fn validate_response(&self, response: &PluginParseResponse, payload_len: usize) -> Result<()> {
        if response.api_version != "packetrecorder.plugin/v1" {
            anyhow::bail!("plugin returned an incompatible API version");
        }
        if !response.confidence.is_finite() || !(0.0..=1.0).contains(&response.confidence) {
            anyhow::bail!("plugin confidence must be between 0 and 1");
        }
        if response.fields.len() > self.limits.max_fields || response.annotations.len() > self.limits.max_annotations {
            anyhow::bail!("plugin response contains too many decoded elements");
        }
        for annotation in &response.annotations {
            let end = (annotation.offset as usize).checked_add(annotation.length as usize)
                .context("plugin annotation overflow")?;
            if end > payload_len {
                anyhow::bail!("plugin annotation is outside the supplied payload");
            }
        }
        Ok(())
    }

    fn stop_process(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn read_exact_with_deadline(
    reader: &mut std::process::ChildStdout,
    mut buffer: &mut [u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    while !buffer.is_empty() {
        let mut descriptor = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { anyhow::bail!("plugin response timed out"); }
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready == 0 {
            anyhow::bail!("plugin response timed out");
        }
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("failed waiting for plugin response");
        }
        let bytes_read = reader.read(buffer)?;
        if bytes_read == 0 {
            anyhow::bail!("plugin closed stdout before completing its response");
        }
        buffer = &mut buffer[bytes_read..];
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_exact_with_deadline(
    reader: &mut std::process::ChildStdout,
    buffer: &mut [u8],
    _deadline: std::time::Instant,
) -> Result<()> {
    reader.read_exact(buffer).context("failed reading plugin response")
}

#[cfg(unix)]
fn write_all_with_deadline(
    writer: &mut std::process::ChildStdin,
    mut buffer: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    while !buffer.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { anyhow::bail!("plugin request timed out"); }
        let mut descriptor = libc::pollfd {
            fd: writer.as_raw_fd(), events: libc::POLLOUT, revents: 0,
        };
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready == 0 { anyhow::bail!("plugin request timed out"); }
        if ready < 0 { return Err(std::io::Error::last_os_error()).context("failed waiting for plugin stdin"); }
        let chunk_len = buffer.len().min(4096);
        let written = unsafe {
            libc::write(writer.as_raw_fd(), buffer.as_ptr().cast(), chunk_len)
        };
        if written < 0 { return Err(std::io::Error::last_os_error()).context("failed writing plugin request"); }
        buffer = &buffer[written as usize..];
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_all_with_deadline(
    writer: &mut std::process::ChildStdin,
    buffer: &[u8],
    _deadline: std::time::Instant,
) -> Result<()> {
    writer.write_all(buffer).context("failed writing plugin request")
}

impl Drop for PluginInstance {
    fn drop(&mut self) {
        self.stop_process();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_instance_without_process() -> PluginInstance {
        PluginInstance {
            name: "test".to_string(), executable: "unused".to_string(), args: Vec::new(),
            limits: PluginLimits::default(), child: None,
            circuit: CircuitBreaker::new(3, std::time::Duration::from_secs(30)),
        }
    }

    #[test]
    fn test_plugin_communication() {
        // Find the example plugin
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("examples/plugins/example_plugin.py");
        let plugin_path = d.to_string_lossy().to_string();

        // Skip if python3 or the script is not available (CI/CD safety)
        if Command::new("python3").arg("--version").output().is_err() {
            return;
        }

        let mut limits = PluginLimits::default();
        limits.timeout_ms = 5_000;
        let mut instance = PluginInstance::new(
            "test_plugin".to_string(),
            "python3".to_string(),
            vec![plugin_path],
            limits,
        ).expect("Failed to create plugin instance");

        let req = PluginParseRequest {
            payload: b"Hello Plugin".to_vec(),
            src_ip: "127.0.0.1".to_string(),
            src_port: 1234,
            dst_ip: "1.1.1.1".to_string(),
            dst_port: 80,
            protocol: "TCP".to_string(),
            api_version: "packetrecorder.plugin/v1".to_string(),
            flow_id: "test-flow".to_string(),
            direction: "initiator_to_responder".to_string(),
            captured_length: 12,
            original_length: 12,
            stream_has_gaps: false,
        };

        let resp = instance.parse(req).expect("Failed to parse");
        
        assert!(resp.success);
        assert_eq!(resp.name, "ExamplePlugin");
        assert_eq!(resp.attributes.get("payload_string").map(|s| s.as_str()), Some("Hello Plugin"));
        assert_eq!(resp.attributes.get("src").map(|s| s.as_str()), Some("127.0.0.1:1234"));
        assert_eq!(resp.api_version, "packetrecorder.plugin/v1");
        assert_eq!(resp.annotations[0].length, 12);
    }

    #[test]
    fn rejects_out_of_bounds_annotations() {
        let instance = test_instance_without_process();
        let response = PluginParseResponse {
            api_version: "packetrecorder.plugin/v1".to_string(),
            confidence: 1.0,
            annotations: vec![plugin_proto::ByteAnnotation {
                offset: 4,
                length: 8,
                field_name: "bad".to_string(),
                sensitive: false,
            }],
            ..Default::default()
        };
        assert!(instance.validate_response(&response, 8).is_err());
    }

    #[test]
    fn accepts_zero_length_annotations_for_filtering() {
        let instance = test_instance_without_process();
        let response = PluginParseResponse {
            api_version: "packetrecorder.plugin/v1".to_string(),
            confidence: 1.0,
            annotations: vec![plugin_proto::ByteAnnotation { offset: 0, length: 0, ..Default::default() }],
            ..Default::default()
        };
        assert!(instance.validate_response(&response, 0).is_ok());
    }

    #[test]
    fn times_out_unresponsive_plugin() {
        if Command::new("python3").arg("--version").output().is_err() {
            return;
        }
        let mut limits = PluginLimits::default();
        limits.timeout_ms = 10;
        let mut instance = PluginInstance::new(
            "sleepy".to_string(),
            "python3".to_string(),
            vec!["-c".to_string(), "import time; time.sleep(1)".to_string()],
            limits,
        ).unwrap();
        let request = PluginParseRequest {
            api_version: "packetrecorder.plugin/v1".to_string(),
            payload: vec![1],
            ..Default::default()
        };
        assert!(instance.parse(request).unwrap_err().to_string().contains("timed out"));
    }

    #[test]
    fn circuit_opens_after_repeated_failures_and_recovers() {
        let mut circuit = CircuitBreaker::new(3, std::time::Duration::from_millis(1));
        assert!(circuit.allow());
        circuit.failure(); circuit.failure(); circuit.failure();
        assert!(!circuit.allow());
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(circuit.allow());
        circuit.success();
        assert_eq!(circuit.consecutive_failures(), 0);
    }

    #[test]
    fn half_open_attempt_starts_a_new_failure_window() {
        let mut circuit = CircuitBreaker::new(3, std::time::Duration::from_millis(1));
        circuit.failure();
        circuit.failure();
        circuit.failure();
        circuit.opened_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));

        assert!(circuit.allow());
        circuit.failure();

        assert_eq!(circuit.consecutive_failures(), 1);
        assert!(circuit.allow());
    }
}
