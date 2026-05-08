use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, GlobalConfig};
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::models::constants::{PLUGIN_S3SCANNER, FINDING_S3_BUCKET};
use crate::utils::tool_detection::detect_tool_system;
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::{Result, Context};
use tracing::{info, warn};
use std::process::Stdio;
use std::time::Duration;
use tokio::time::timeout;
use std::collections::HashSet;
use std::io::Write;
use tempfile::NamedTempFile;

pub struct S3BucketScanner {
    binary_path: Option<String>,
    wordlist_path: Option<String>,
}

impl S3BucketScanner {
    pub fn new<M: crate::utils::executor::ExecutorMode>(config: &GlobalConfig<M>) -> Self {
        let binary_path = config.s3scanner_path.clone().or_else(|| {
            match detect_tool_system("s3scanner") {
                Ok(Some(path)) => Some(path.to_string_lossy().into_owned()),
                _ => None,
            }
        });

        Self {
            binary_path,
            wordlist_path: config.s3scanner_wordlist_path.clone(),
        }
    }

    /// STRIKE-TIME FIX: Smart mutation engine with sanitization and lowercase enforcement
    fn generate_mutations(&self, raw_host: &str) -> Vec<String> {
        let host = raw_host.to_lowercase();
        let safe_host = host.replace('.', "-");
        
        // STRIKE-TIME FIX: Smart stem extraction using PSL (addr crate)
        let stem = if let Ok(domain) = addr::parse_domain_name(&host) {
            domain.root().and_then(|r| r.split('.').next()).unwrap_or(host.split('.').rev().nth(1).unwrap_or(host.split('.').next().unwrap_or(&host)))
        } else {
            host.split('.').rev().nth(1).unwrap_or(host.split('.').next().unwrap_or(&host))
        }.to_string();

        let mut templates = HashSet::new();
        
        // 12 canonical templates as defined in Rev 3
        templates.insert(safe_host.clone());
        templates.insert(format!("{}-backup", safe_host));
        templates.insert(format!("{}-logs", safe_host));
        templates.insert(format!("{}-assets", safe_host));
        templates.insert(format!("{}-data", safe_host));
        templates.insert(format!("{}-dev", safe_host));
        
        templates.insert(stem.to_string());
        templates.insert(format!("{}-backup", stem));
        templates.insert(format!("{}backup", stem));
        templates.insert(format!("{}-prod", stem));
        templates.insert(format!("{}-staging", stem));
        templates.insert(format!("{}test", stem));

        // STRIKE-TIME FIX: Minimum length validation (S3 buckets must be >= 3 chars)
        templates.into_iter().filter(|t| t.len() >= 3).collect()
    }

    /// Map S3Scanner permissions to Mimikri Severity levels (JSON v3 compliant)
    /// 0: Allowed (Public), 1: Denied (Private), 2: Error/Unknown
    fn map_severity(&self, bucket_obj: &serde_json::Value) -> Severity {
        let is_public_write = bucket_obj.get("perm_all_users_write").and_then(|v| v.as_u64()).map(|v| v == 0).unwrap_or(false) ||
                              bucket_obj.get("perm_all_users_full_control").and_then(|v| v.as_u64()).map(|v| v == 0).unwrap_or(false);
        
        if is_public_write {
            return Severity::Critical;
        }

        let is_public_read = bucket_obj.get("perm_all_users_read").and_then(|v| v.as_u64()).map(|v| v == 0).unwrap_or(false);
        if is_public_read {
            return Severity::High;
        }

        Severity::Medium
    }

    fn is_private_or_local(host: &str) -> bool {
        if host == "localhost" { return true; }
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            let octets = ip.octets();
            return ip.is_loopback()
                || octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168);
        }
        false
    }
}

#[async_trait]
impl ScannerPlugin for S3BucketScanner {
    fn name(&self) -> &'static str {
        PLUGIN_S3SCANNER
    }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: self.name().to_string(),
            description: "S3BucketScanner: Audits S3 buckets for public access and misconfigurations.".to_string(),
            target_type: crate::models::TargetType::Cloud,
            risk_level: RiskLevel::Low,
            layer: ScanLayer::Discovery,
            category: "Enumeration".to_string(),
            expected_duration: Duration::from_secs(660),
            capabilities: self.capabilities(),
            cost: 5,
            mitre_attacks: vec!["T1530".to_string()],
            exploit_difficulty: RiskLevel::Low,
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::CloudAudit]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        if let Some(path) = &self.binary_path {
            if tokio::fs::try_exists(path).await.unwrap_or(false) {
                return Ok(true);
            }
        }
        warn!("S3Scanner binary not found. Skipping S3BucketScanner.");
        Ok(false)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // STRIKE-TIME FIX: Robust RFC1918 and local filtering
        if Self::is_private_or_local(&target.host) {
            return Ok(vec![]);
        }

        info!("S3BucketScanner: initiating cloud audit for {}", target.host);

        let bin_path = self.binary_path.as_ref()
            .context("S3BucketScanner invariant violated: binary_path is None during scan")?;

        // Mode A/B Trigger Logic
        let (temp_file, final_wordlist_path) = if let Some(path) = &self.wordlist_path {
            if tokio::fs::try_exists(path).await.unwrap_or(false) {
                info!("S3BucketScanner: Mode A (External Wordlist)");
                (None, path.clone())
            } else {
                info!("S3BucketScanner: Mode B (Mutation Generator) - Reason: Wordlist path invalid");
                let mut tmp = NamedTempFile::new().context("Failed to create temp wordlist for S3Scanner")?;
                let mutations = self.generate_mutations(&target.host);
                writeln!(tmp, "{}", mutations.join("\n"))?;
                let path = tmp.path().to_string_lossy().to_string();
                (Some(tmp), path)
            }
        } else {
            info!("S3BucketScanner: Mode B (Mutation Generator) - Reason: No wordlist configured");
            let mut tmp = NamedTempFile::new().context("Failed to create temp wordlist for S3Scanner")?;
            let mutations = self.generate_mutations(&target.host);
            writeln!(tmp, "{}", mutations.join("\n"))?;
            let path = tmp.path().to_string_lossy().to_string();
            (Some(tmp), path)
        };

        let mut cmd = tokio::process::Command::new(bin_path);
        cmd.arg("-bucket-file").arg(&final_wordlist_path)
            .arg("-json")
            .arg("-provider").arg("aws")
            .arg("-threads").arg("4") // STRIKE-TIME FIX: OPSEC explicit concurrency
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Env-Leak Guard: Do not log the cmd object directly
        info!("S3BucketScanner: spawning binary at {}", bin_path);

        let output_result = timeout(Duration::from_secs(600), cmd.spawn()?.wait_with_output()).await;

        // Ensure temp file lives until process completes
        drop(temp_file);

        let output = match output_result {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                warn!("S3BucketScanner: execution error for {}: {}", target.host, e);
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("S3BucketScanner: execution timed out for {}", target.host);
                return Ok(vec![]);
            }
        };

        // STRIKE-TIME FIX: Stderr capture warn
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                warn!("S3BucketScanner stderr: {}", stderr);
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut findings = Vec::new();

        for line in stdout.lines() {
            if line.trim().is_empty() { continue; }

            // NDJSON Parse Strategy: Verified keys for sa7mon v3
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(entry) => {
                    if let Some(bucket_obj) = entry.get("bucket") {
                        let name = bucket_obj.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                        // exists can be int (0: exists, 1: not found, 2: error) or boolean in some versions
                        let exists = bucket_obj.get("exists").and_then(|v| {
                            v.as_bool().or_else(|| v.as_u64().map(|n| n == 0))
                        }).unwrap_or(false);

                        if exists {
                            let severity = self.map_severity(bucket_obj);
                            
                            findings.push(Finding::new(
                                FINDING_S3_BUCKET,
                                Category::Misconfiguration,
                                severity,
                                &format!("Public S3 bucket discovered: {}", name),
                                serde_json::json!({
                                    "bucket_name": name,
                                    "bucket_data": bucket_obj,
                                    "raw_entry": entry
                                })
                            ).with_tactical_path("Verify the contents of the public bucket and check for sensitive data leakage."));
                        }
                    }
                }
                Err(e) => {
                    warn!("S3BucketScanner: malformed NDJSON line: {} | Error: {}", line, e);
                }
            }
        }

        info!("S3BucketScanner: found {} S3 buckets for {}", findings.len(), target.host);
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_generator() {
        let scanner = S3BucketScanner { binary_path: None, wordlist_path: None };
        let mutations = scanner.generate_mutations("Example.COM");
        assert!(mutations.contains(&"example-com".to_string()));
        assert!(mutations.contains(&"example-backup".to_string()));
        assert!(mutations.contains(&"example-prod".to_string()));
        // Lowercase check
        for m in &mutations {
            assert_eq!(m.to_lowercase(), *m);
        }
        // Length check
        for m in &mutations {
            assert!(m.len() >= 3);
        }
    }

    #[test]
    fn test_severity_mapping() {
        let scanner = S3BucketScanner { binary_path: None, wordlist_path: None };
        
        let critical = scanner.map_severity(&serde_json::json!({"perm_all_users_write": 0}));
        assert_eq!(critical, Severity::Critical);

        let high = scanner.map_severity(&serde_json::json!({"perm_all_users_read": 0, "perm_all_users_write": 1}));
        assert_eq!(high, Severity::High);

        let medium = scanner.map_severity(&serde_json::json!({"perm_all_users_read": 1, "perm_all_users_write": 1}));
        assert_eq!(medium, Severity::Medium);
    }
}
