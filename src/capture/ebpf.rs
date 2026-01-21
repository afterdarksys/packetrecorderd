#[cfg(target_os = "linux")]
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

#[cfg(target_os = "linux")]
pub struct EbpfCapture {
    bpf: Bpf,
    interface: String,
}

#[cfg(target_os = "linux")]
impl EbpfCapture {
    pub fn new(interface: &str) -> Result<Self> {
        info!("Initializing eBPF capture on {}", interface);

        // In a real build, we would include the compiled BPF object file.
        // For now, we'll placeholder this. The user needs to compile the BPF program separately.
        // Typically: include_bytes_aligned!(concat!(env!("OUT_DIR"), "/packetrecorder-ebpf"))
        
        // Simulating loading from a file for now, or failing if not present
        let mut bpf = Bpf::load(&[]) 
            .or_else(|_| Bpf::load_file("packetrecorder-ebpf.o"))
            .context("Failed to load eBPF program. Ensure 'packetrecorder-ebpf.o' is present.")?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            // This can fail if the eBPF program doesn't have logging enabled/compiled
            warn!("Failed to initialize eBPF logger: {}", e);
        }

        let program: &mut Xdp = bpf.program_mut("xdp_packet_recorder").unwrap().try_into()?;
        program.load()?;
        program.attach(interface, XdpFlags::default())
            .context(format!("Failed to attach XDP program to {}", interface))?;

        Ok(Self {
            bpf,
            interface: interface.to_string(),
        })
    }
}

// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct EbpfCapture;

#[cfg(not(target_os = "linux"))]
impl EbpfCapture {
    pub fn new(_interface: &str) -> anyhow::Result<Self> {
        anyhow::bail!("eBPF capture is only supported on Linux");
    }
}
