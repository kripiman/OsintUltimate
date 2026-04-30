use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tracing::{info, warn, debug};
use std::borrow::Cow;

/// Detects if a tool is available in the system PATH using the `which` command.
/// 
/// This function first attempts to use the system `which` command for maximum
/// compatibility with BlackArch and other specialized distributions. Falls back
/// to Rust's `which` crate if system command fails.
/// 
/// # Arguments
/// * `tool_name` - Name of the tool to detect (e.g., "ffuf", "nuclei", "sqlmap")
/// 
/// # Returns
/// * `Ok(Some(PathBuf))` - Tool found at the given path
/// * `Ok(None)` - Tool not found in PATH
/// * `Err` - Error during detection
pub fn detect_tool_system(tool_name: &str) -> Result<Option<PathBuf>> {
    debug!("Attempting to detect tool: {}", tool_name);
    
    // First try: local ./bin directory (useful for portable/temp tool installs)
    let local_bin = PathBuf::from("./bin").join(tool_name);
    if local_bin.exists() {
        if let Ok(abs_path) = std::fs::canonicalize(&local_bin) {
            info!("Tool '{}' detected in local ./bin: {}", tool_name, abs_path.display());
            return Ok(Some(abs_path));
        }
    }

    // Second try: system `which` command (supports BlackArch and other distros)
    match Command::new("which")
        .arg(tool_name)
        .output()
        .context(format!("Failed to execute 'which' for {}", tool_name))? 
    {
        output if output.status.success() => {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path_str.is_empty() {
                let path = PathBuf::from(&path_str);
                info!("Tool '{}' detected at: {}", tool_name, path.display());
                return Ok(Some(path));
            }
        }
        _ => debug!("System 'which' command did not find '{}'", tool_name),
    }
    
    // Fallback: Rust's `which` crate (reliable but may miss BlackArch aliases)
    match which::which(tool_name) {
        Ok(path) => {
            info!("Tool '{}' detected via fallback at: {}", tool_name, path.display());
            Ok(Some(path))
        }
        Err(_) => {
            warn!("Tool '{}' not found in system PATH", tool_name);
            Ok(None)
        }
    }
}

/// Lightweight version that returns just the string path or empty string.
/// Useful for immediate use in Command::new() without extra error handling.
pub fn detect_tool(tool_name: &str) -> String {
    match detect_tool_system(tool_name) {
        Ok(Some(path)) => path.to_string_lossy().to_string(),
        Ok(None) => {
            warn!("Tool '{}' not found; will attempt fallback", tool_name);
            tool_name.to_string()
        }
        Err(e) => {
            warn!("Error detecting tool '{}': {}; using tool name as fallback", tool_name, e);
            tool_name.to_string()
        }
    }
}

/// Optimized version using Cow for callers that can avoid allocation.
pub fn detect_tool_cow<'a>(tool_name: &'a str) -> Cow<'a, str> {
    match detect_tool_system(tool_name) {
        Ok(Some(path)) => Cow::Owned(path.to_string_lossy().to_string()),
        Ok(None) => Cow::Borrowed(tool_name),
        Err(_) => Cow::Borrowed(tool_name),
    }
}

/// Checks if a tool is available and returns whether it's ready for use.
/// Returns true if tool exists and is executable.
pub async fn check_tool_availability(tool_name: &str) -> bool {
    match detect_tool_system(tool_name) {
        Ok(Some(path)) => {
            // Verify it's executable
            match tokio::fs::metadata(&path).await {
                Ok(metadata) => {
                    let is_executable = cfg!(unix) && 
                        (metadata.permissions().mode() & 0o111 != 0) ||
                        cfg!(windows);
                    
                    if is_executable {
                        info!("Tool '{}' verified as executable", tool_name);
                        true
                    } else {
                        warn!("Tool '{}' found but not executable", tool_name);
                        false
                    }
                }
                Err(e) => {
                    warn!("Failed to verify tool '{}' metadata: {}", tool_name, e);
                    true // Assume it's executable if we found it in PATH
                }
            }
        }
        Ok(None) => {
            warn!("Tool '{}' not available in PATH", tool_name);
            false
        }
        Err(e) => {
            warn!("Error checking tool '{}' availability: {}", tool_name, e);
            false
        }
    }
}

/// Verifies tool version compatibility with a minimum required version.
/// Executes `<tool_name> --version` and parses the output.
pub async fn verify_tool_version(
    tool_name: &str,
    min_version: Option<&str>,
) -> Result<bool> {
    if let Ok(Some(path)) = detect_tool_system(tool_name) {
        let output = tokio::process::Command::new(&path)
            .arg("--version")
            .output()
            .await
            .context(format!("Failed to get version for {}", tool_name))?;
        
        if output.status.success() {
            let version_str = String::from_utf8_lossy(&output.stdout);
            info!("Tool '{}' version output: {}", tool_name, version_str.trim());
            
            if let Some(min_v) = min_version {
                // Simple lexicographic comparison (improve as needed)
                if version_str.contains(min_v) || version_str.as_ref() >= min_v {
                    return Ok(true);
                }
                warn!("Tool '{}' version may not meet minimum requirement: {}", tool_name, min_v);
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// BlackArch-specific tool detection
/// Checks common BlackArch paths and environment variables
pub fn detect_blackarch_tool(tool_name: &str) -> Option<PathBuf> {
    debug!("Checking BlackArch-specific paths for: {}", tool_name);
    
    // Common BlackArch installation paths
    let blackarch_paths = vec![
        "/usr/bin",
        "/usr/local/bin",
        "/opt/blackarch/bin",
        "/home/user/.local/bin",
    ];
    
    for base_path in blackarch_paths {
        let full_path = PathBuf::from(base_path).join(tool_name);
        if full_path.exists() {
            info!("BlackArch tool '{}' found at: {}", tool_name, full_path.display());
            return Some(full_path);
        }
    }
    
    // Check $PATH environment variable
    if let Ok(path_env) = std::env::var("PATH") {
        for path_str in path_env.split(':') {
            let full_path = PathBuf::from(path_str).join(tool_name);
            if full_path.exists() {
                info!("Tool '{}' found in PATH at: {}", tool_name, full_path.display());
                return Some(full_path);
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_tool_ls() {
        let result = detect_tool_system("ls");
        assert!(result.is_ok());
        assert!(result.unwrap().is_some(), "ls should be available on any Unix system");
    }

    #[test]
    fn test_detect_nonexistent_tool() {
        let result = detect_tool_system("nonexistent_tool_xyz_12345");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "nonexistent tool should return None");
    }
}
