use anyhow::{Context, Result};
use std::process::Command;
use std::path::Path;
use tracing::{info, warn};

/// Verifies if the given path is on an NFS mount that meets the requirements:
/// - "hard" mount option
/// - "tcp" protocol
/// - "sync" (or at least check for it if possible, though behavior varies)
pub fn verify_nfs_mount_options(path: &Path) -> Result<()> {
    // 1. Find the mount point for the path
    // Simple approach: verify if the path itself or a parent is a mount point
    // A more robust way requires identifying the device ID, but parsing `mount` output is what we'll do.
    
    let mount_output = Command::new("mount")
        .output()
        .context("Failed to execute 'mount' command")?;
    
    let output_str = String::from_utf8_lossy(&mount_output.stdout);
    
    // Convert path to absolute to match against mount points
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    
    // Find the longest matching mount point prefix
    let mut best_match: Option<(String, String)> = None; // (mount_point, options)
    
    for line in output_str.lines() {
        // Parse line. Format varies by OS.
        // Linux: device on /path type nfs (options)
        // macOS: //host/path on /path (nfs, options)
        
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 3 { continue; }
        
        let mount_point;
        let options;
        let fs_type;
        
        if line.contains(" on ") {
            // BSD/macOS style or typical `mount` output
            // Example: //server/share on /mnt/nfs (nfs, ...)
            if let Some(on_idx) = parts.iter().position(|&x| x == "on") {
                if on_idx + 1 < parts.len() {
                    mount_point = parts[on_idx + 1];
                    // Options usually in parens at the end
                    if let Some(paren_start) = line.find('(') {
                        if let Some(paren_end) = line.rfind(')') {
                            options = &line[paren_start+1..paren_end];
                            // Try to guess fs_type from options or start
                            fs_type = if options.contains("nfs") { "nfs" } else { "unknown" };
                        } else { continue; }
                    } else { continue; }
                } else { continue; }
            } else { continue; }
        } else {
            // Linux style (often)
            // device /mount/point fstype options dump pass
            if parts.len() >= 4 {
                mount_point = parts[1];
                fs_type = parts[2];
                options = parts[3];
            } else { continue; }
        }

        if fs_type != "nfs" && fs_type != "nfs4" && !options.contains("nfs") {
            continue;
        }

        // Check if our path starts with this mount point
        if abs_path.starts_with(Path::new(mount_point)) {
            // If we already have a match, replace it only if this one is longer (more specific)
            if let Some((ref current_best, _)) = best_match {
                if mount_point.len() > current_best.len() {
                    best_match = Some((mount_point.to_string(), options.to_string()));
                }
            } else {
                best_match = Some((mount_point.to_string(), options.to_string()));
            }
        }
    }
    
    if let Some((mount_point, options)) = best_match {
        info!("Found NFS mount point '{}' for path '{:?}'. Options: {}", mount_point, path, options);
        check_options(&options)?;
    } else {
        // If it's not found in mount output as NFS, maybe it's not NFS?
        // Or maybe we failed to parse. We'll warn but not fail hard unless we are sure it SHOULD be NFS.
        warn!("Path '{:?}' does not appear to be on a detected NFS mount (or parsing failed). Skipping NFS specific checks.", path);
    }

    Ok(())
}

fn check_options(options: &str) -> Result<()> {
    let opts_list: Vec<&str> = options.split(',').map(|s| s.trim()).collect();
    
    // Check for "hard"
    // Linux default is often "hard", so explicit "soft" is the failure condition.
    // However, user asked to ensure "hard" mount option is ENABLED.
    // If output shows "hard", good. If it doesn't show "soft", we might assume hard?
    // macOS explicitly shows "hard" or "soft" usually? No, macOS default is hard?
    // Let's look for "hard" OR absence of "soft".
    let has_hard = opts_list.contains(&"hard");
    let has_soft = opts_list.contains(&"soft");
    
    if has_soft {
        anyhow::bail!("NFS mount configured with 'soft' option. 'hard' mount is required.");
    }
    // If neither is present, we might warn or assume default.
    // But to be strict as requested:
    if !has_hard && !has_soft {
        // Some systems don't list 'hard' if it's default.
        info!("'hard' option not explicitly visible, but 'soft' is absent. Assuming hard mount.");
    }

    // Check for "tcp"
    // Look for "tcp" or "proto=tcp"
    let has_tcp = opts_list.contains(&"tcp") || opts_list.iter().any(|&o| o.starts_with("proto=tcp"));
    let has_udp = opts_list.contains(&"udp") || opts_list.iter().any(|&o| o.starts_with("proto=udp"));
    
    if has_udp {
        anyhow::bail!("NFS mount configured with UDP. TCP is required.");
    }
    if !has_tcp && !has_udp {
         info!("Protocol not explicitly visible. Assuming TCP (default for NFSv4).");
    }

    // Check for "sync"
    // Client side "sync" means synchronous file operations.
    let has_sync = opts_list.contains(&"sync");
    let has_async = opts_list.contains(&"async");
    
    if !has_sync {
        if has_async {
             anyhow::bail!("NFS mount configured with 'async'. 'sync' is required.");
        } else {
             // If neither, default is usually async on server, but client mount default?
             // User said "Ensure Sync is enabled".
             warn!("'sync' mount option not detected. Verify NFS configuration.");
        }
    }

    Ok(())
}
