use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// V14.1 Sovereign Policy: Trait-based security for offensive operations.
pub trait PolicyProvider: Send + Sync {
    /// Validates if a binary and its arguments are allowed under current ROE.
    fn validate_command(&self, binary: &str, args: &[String]) -> Result<()>;
    
    /// Checks if a path or URL sub-component is safe (SSRF, Path Traversal).
    fn is_path_safe(&self, path: &str) -> bool;
    
    /// Checks if a hostname or IP is within the authorized scope (Placeholder for future ScopeProvider integration).
    fn is_target_allowed(&self, target: &str) -> bool;
}

/// Static implementation of the Sovereign Policy (V14.1 initial consolidation).
pub struct StaticPolicy {
    allowed_binaries: HashSet<String>,
    allowed_nmap_flags: HashSet<String>,
}

impl StaticPolicy {
    pub fn new() -> Self {
        let allowed_binaries = vec!["curl", "nmap", "ping", "dig", "nc", "ssh"]
            .into_iter().map(String::from).collect();
            
        let allowed_nmap_flags = vec![
            "-sV", "-Pn", "-n", "--open", "--version-light", 
            "-sS", "-F", "--reason", "-T4", "-A", "-sC", "-p-",
            "--min-rate", "--max-retries", "-O"
        ].into_iter().map(String::from).collect();

        Self {
            allowed_binaries,
            allowed_nmap_flags,
        }
    }
}

static PATH_SAFE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-\._/~%\?&=+]+$").unwrap());

impl PolicyProvider for StaticPolicy {
    fn validate_command(&self, binary: &str, args: &[String]) -> Result<()> {
        if !self.allowed_binaries.contains(binary) {
            anyhow::bail!("V14.1 Policy Violation: Binary '{}' is not in the authorized whitelist.", binary);
        }

        if binary == "nmap" {
            for arg in args {
                if arg.starts_with('-') {
                    // Extract flag part (e.g. -p80 -> -p)
                    let _flag = if arg.len() >= 2 && !arg.starts_with("--") {
                        &arg[0..2]
                    } else if arg.contains('=') {
                         arg.split('=').next().unwrap_or(arg)
                    } else {
                        arg.as_str()
                    };

                    // Some flags like -p, -T4, -D are allowed even if they have attached data
                    let is_allowed = self.allowed_nmap_flags.contains(arg) 
                        || arg.starts_with("-p") 
                        || arg.starts_with("-T")
                        || arg.starts_with("-D")
                        || arg.starts_with("--min-rate");

                    if !is_allowed {
                         anyhow::bail!("V14.1 Policy Violation: Nmap flag '{}' is not authorized.", arg);
                    }
                }
            }
        }

        Ok(())
    }

    fn is_path_safe(&self, path: &str) -> bool {
        if path.contains("..") {
            return false;
        }
        PATH_SAFE_RE.is_match(path)
    }

    fn is_target_allowed(&self, _target: &str) -> bool {
        // V14.1: Scope is handled at a higher level (Agent/Orchestrator), 
        // but this hook is ready for deep integration.
        true
    }
}
