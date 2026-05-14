use anyhow::Result;
pub mod scope_syncer;
use chrono::Timelike;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct PolicyJson {
    in_scope: Vec<ScopeTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeTarget {
    pub target: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationContact {
    pub name: String,
    pub role: String,
    pub channel: String,
    pub available: String,  // "24/7", "Mon-Fri 09:00-18:00"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeconflictionPlan {
    pub engagement_name: String,
    pub soc_contact: String,
    pub deconfliction_code: String,
    pub notification_procedure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoE {
    pub engagement_name: String,
    pub client: String,
    pub start_date: String,
    pub end_date: String,
    pub testing_window: String,         // "Mon-Fri 09:00-18:00 UTC"
    pub in_scope: Vec<ScopeTarget>,
    pub out_of_scope: Vec<ScopeTarget>,
    pub prohibited_actions: Vec<String>,
    pub permitted_actions: Vec<String>,
    pub escalation_contacts: Vec<EscalationContact>,
    pub incident_procedure: String,
    pub authorization_reference: String,
    pub cleanup_required: bool,
    pub deconfliction: Option<DeconflictionPlan>,
}

/// V14.1 Sovereign Policy: Trait-based security for offensive operations.
pub trait PolicyProvider: Send + Sync {
    /// Validates if a binary and its arguments are allowed under current ROE.
    fn validate_command(&self, binary: &str, args: &[String]) -> Result<()>;
    
    /// Checks if a path or URL sub-component is safe (SSRF, Path Traversal).
    fn is_path_safe(&self, path: &str) -> bool;
    
    /// Checks if a hostname or IP is within the authorized scope (Placeholder for future ScopeProvider integration).
    fn is_target_allowed(&self, target: &str) -> bool;

    /// V14.5 Decepticon: Verifies if current time is within the ROE testing window.
    fn is_within_testing_window(&self) -> bool;

    /// Returns the formal Rules of Engagement if defined.
    fn get_roe(&self) -> Option<RoE>;
}

/// V14.6 Decepticon: Hot-reloadable policy wrapper.
pub struct ReloadablePolicy {
    inner: std::sync::RwLock<StaticPolicy>,
    policy_path: Option<std::path::PathBuf>,
}

impl ReloadablePolicy {
    pub fn new(path: Option<&str>) -> Self {
        let policy_path = path.map(|p| std::path::Path::new(p).to_path_buf());
        let initial = StaticPolicy::from_file(path);
        Self {
            inner: std::sync::RwLock::new(initial),
            policy_path,
        }
    }

    pub fn reload(&self) {
        tracing::info!("🛡️ V14.6 POLICY: Reloading policy from file...");
        let path_str = self.policy_path.as_deref().and_then(|p| p.to_str());
        let new_policy = StaticPolicy::from_file(path_str);
        match self.inner.write() {
            Ok(mut lock) => {
                *lock = new_policy;
                tracing::info!("🛡️ V14.6 POLICY: Reload successful.");
            }
            Err(e) => tracing::error!("❌ V14.6 POLICY: Failed to acquire write lock for reload: {}", e),
        }
    }
}

impl PolicyProvider for ReloadablePolicy {
    fn validate_command(&self, binary: &str, args: &[String]) -> Result<()> {
        self.inner.read().map_err(|e| anyhow::anyhow!("Poisoned lock: {}", e))?.validate_command(binary, args)
    }

    fn is_path_safe(&self, path: &str) -> bool {
        self.inner.read().map(|p| p.is_path_safe(path)).unwrap_or(false)
    }

    fn is_target_allowed(&self, target: &str) -> bool {
        self.inner.read().map(|p| p.is_target_allowed(target)).unwrap_or(false)
    }

    fn is_within_testing_window(&self) -> bool {
        self.inner.read().map(|p| p.is_within_testing_window()).unwrap_or(true)
    }

    fn get_roe(&self) -> Option<RoE> {
        self.inner.read().ok().and_then(|p| p.get_roe())
    }
}

/// Static implementation of the Sovereign Policy (V14.1 initial consolidation).
pub struct StaticPolicy {
    allowed_binaries: HashSet<String>,
    allowed_nmap_flags: HashSet<String>,
    in_scope_patterns: Vec<Regex>,
    allowed_roots: HashSet<String>, // Phase C: eTLD+1 roots (e.g., example.com)
    roe: Option<RoE>,
}

impl Default for StaticPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticPolicy {
    pub fn new() -> Self {
        Self::from_file(None)
    }

    pub fn from_file(path: Option<&str>) -> Self {
        let allowed_binaries = vec![
            "curl", "nmap", "ping", "dig", "nc", "ssh", "which",
            "apktool", "jadx", "apkleaks", "drozer",
            "syft", "grype", "cosign",
            "whatweb", "ffuf", "inql", "graphw00f", "crackql", "schemathesis",
            "katana", "nuclei", "interactsh-client", "amass", "subfinder",
            "httpx", "ppmap", "corsy", "linkfinder", "secretfinder", "jsluice",
            "snallygaster", "wpsec", "tsunami", "crlfuzz", "arjun", "x8",
        ].into_iter().map(String::from).collect();
            
        let allowed_nmap_flags = vec![
            "-sV", "-Pn", "-n", "--open", "--version-light", 
            "-sS", "-F", "--reason", "-T4", "-A", "-sC", "-p-",
            "--min-rate", "--max-retries", "-O"
        ].into_iter().map(String::from).collect();

        let mut in_scope_patterns = Vec::new();
        let mut allowed_roots = HashSet::new();

        // V14.2: Load scope from policy.json or provided path
        let policy_path = if let Some(p) = path {
            Path::new(p).to_path_buf()
        } else {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("policy.json")))
                .filter(|p| p.exists())
                .unwrap_or_else(|| Path::new("policy.json").to_path_buf())
        };

        if policy_path.exists() {
            tracing::info!("🛡️ V14.2 SCOPE: Loading policy from {:?}", policy_path);
            if let Ok(content) = std::fs::read_to_string(&policy_path) {
                if let Ok(policy) = serde_json::from_str::<PolicyJson>(&content) {
                    for entry in policy.in_scope {
                        let target = entry.target.trim();
                        
                        // Phase C: If the target is a domain/wildcard-domain, extract the PSL root
                        let domain_str = target.trim_start_matches("*.");
                        if let Ok(domain) = addr::parse_domain_name(domain_str) {
                            if let Some(root) = domain.root() {
                                tracing::info!("🛡️ V14.2 SCOPE: Adding PSL authorized root: {}", root);
                                allowed_roots.insert(root.to_string());
                            }
                        }

                        // Fallback/Legacy: Regex for complex patterns or IPs
                        let pattern = target
                            .replace(".", "\\.")
                            .replace("*", ".*");
                        if let Ok(re) = Regex::new(&format!("^{}$", pattern)) {
                            in_scope_patterns.push(re);
                        }
                    }
                }
            }
        } else if path.is_some() {
            tracing::error!("❌ V14.2 SCOPE: Specified policy file {:?} NOT FOUND!", policy_path);
        }

        // V14.5: Load RoE from workspace/plan/roe.json
        let mut roe = None;
        let roe_path = Path::new("workspace/plan/roe.json");
        if roe_path.exists() {
            if let Ok(content) = std::fs::read_to_string(roe_path) {
                if let Ok(parsed_roe) = serde_json::from_str::<RoE>(&content) {
                    tracing::info!("🛡️ V14.5 ROE: Loaded rules of engagement for {}", parsed_roe.engagement_name);
                    roe = Some(parsed_roe);
                }
            }
        }

        Self {
            allowed_binaries,
            allowed_nmap_flags,
            in_scope_patterns,
            allowed_roots,
            roe,
        }
    }

    pub fn with_roe(mut self, roe: RoE) -> Self {
        self.roe = Some(roe);
        self
    }
}

static PATH_SAFE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-zA-Z0-9\-\._/~%\?&=+]+$").unwrap());

impl PolicyProvider for StaticPolicy {
    fn validate_command(&self, binary: &str, args: &[String]) -> Result<()> {
        let binary_name = Path::new(binary)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(binary);

        if !self.allowed_binaries.contains(binary_name) {
            anyhow::bail!("V14.1 Policy Violation: Binary '{}' (name: '{}') is not in the authorized whitelist.", binary, binary_name);
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

    fn is_target_allowed(&self, target: &str) -> bool {
        // V14.2: Real Scope Validation using PSL + Regex fallbacks
        if self.in_scope_patterns.is_empty() && self.allowed_roots.is_empty() {
            // Sprint 2: Fail-Closed Requirement
            tracing::warn!("🛡️ V14.2 POLICY_MISSING: No policy.json defined. All targets rejected (Fail-Closed).");
            return false;
        }

        // Phase C: PSL Domain Check (Preferred)
        if let Ok(domain) = addr::parse_domain_name(target) {
            if let Some(root) = domain.root() {
                let root_str: &str = root;
                if self.allowed_roots.contains(root_str) {
                    return true;
                }
            }
        }

        // Fallback: Regex matching (Handles IPs, partial matches, or manually defined patterns)
        for re in &self.in_scope_patterns {
            if re.is_match(target) {
                return true;
            }
        }

        tracing::warn!("V14.2 SCOPE VIOLATION: Target '{}' is NOT in scope!", target);
        false
    }

    fn is_within_testing_window(&self) -> bool {
        let roe = match &self.roe {
            Some(r) => r,
            None => return true, // No RoE, assume development mode
        };

        if roe.testing_window.to_lowercase() == "24/7" {
            return true;
        }

        // Simplistic implementation for V14.5: Check if current hour is within window
        // Format expected: "Mon-Fri 09:00-18:00 UTC"
        let now = chrono::Utc::now();
        let day = now.format("%a").to_string();
        let hour = now.hour();

        if roe.testing_window.contains("Mon-Fri") {
            let weekdays = ["Mon", "Tue", "Wed", "Thu", "Fri"];
            if !weekdays.contains(&day.as_str()) {
                return false;
            }
        }

        // Hour range check "09:00-18:00"
        if let Some(range) = roe.testing_window.split_whitespace().nth(1) {
            let mut parts = range.split('-');
            if let (Some(start_str), Some(end_str)) = (parts.next(), parts.next()) {
                if let (Ok(start), Ok(end)) = (
                    start_str.split(':').next().unwrap_or("0").parse::<u32>(),
                    end_str.split(':').next().unwrap_or("23").parse::<u32>(),
                ) {
                    return hour >= start && hour < end;
                }
            }
        }

        true
    }

    fn get_roe(&self) -> Option<RoE> {
        self.roe.clone()
    }
}
