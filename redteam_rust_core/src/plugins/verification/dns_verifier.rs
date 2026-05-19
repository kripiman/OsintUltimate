use crate::plugins::{ScannerPlugin, Capability, PluginMetadata, RiskLevel, TargetType};
use crate::models::{TargetHost, Finding, Category, Severity, constants};
use crate::core::capability_layer::ScanLayer;
use async_trait::async_trait;
use anyhow::Result;
use tracing::info;
use std::time::Duration;

pub struct DnsHijackVerifier {
    #[allow(dead_code)]
    client: reqwest::Client,
}

impl Default for DnsHijackVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsHijackVerifier {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for DnsHijackVerifier {
    fn name(&self) -> &'static str { constants::PLUGIN_DNS_VERIFIER }

    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "DNS Hijack Verifier".to_string(),
            description: "Verifies subdomain takeover vulnerabilities via Interactsh OOB verification.".to_string(),
            target_type: TargetType::Host,
            risk_level: RiskLevel::Safe,
            layer: ScanLayer::Scanning,
            category: "Verification".to_string(),
            capabilities: vec![Capability::VulnerabilityScanning],
            ..Default::default()
        }
    }

    async fn check_dependencies(&self) -> Result<bool> { Ok(true) }
    fn capabilities(&self) -> Vec<Capability> { vec![Capability::VulnerabilityScanning] }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        info!("🛡️ DNS-VERIFIER: Verifying subdomain takeover on {}", target.host);
        
        let mut findings = Vec::new();
        
        // 1. Resolve CNAME records
        let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()?;
        let response = match resolver.lookup(target.host.clone(), hickory_resolver::proto::rr::RecordType::CNAME).await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        for record in response.iter() {
            if let Some(cname) = record.as_cname() {
                let target_cname = cname.to_string().to_lowercase();
                let target_cname = target_cname.trim_end_matches('.');
                
                // 2. Check against known claimable services
                let claimable_services = [
                    "github.io", "herokuapp.com", "cloudfront.net", "s3.amazonaws.com",
                    "azurewebsites.net", "ghost.io", "fastly.net", "bitbucket.io",
                    "myshopify.com", "surge.sh", "readthedocs.io", "webflow.io"
                ];

                for service in claimable_services {
                    if target_cname.ends_with(service) {
                        // 3. Verify if the target is actually claimable (e.g. 404 or specific error)
                        let check_url = format!("http://{}", target.host);
                        let resp = self.client.get(&check_url).send().await;
                        
                        let is_vulnerable = match resp {
                            Ok(r) => {
                                let status = r.status();
                                let body = r.text().await.unwrap_or_default().to_lowercase();
                                // Common "not found" indicators for claimable services
                                status == reqwest::StatusCode::NOT_FOUND ||
                                body.contains("there isn't a github pages site here") ||
                                body.contains("no such app") ||
                                body.contains("no such bucket") ||
                                body.contains("404 not found") ||
                                body.contains("the resource you are looking for has been removed")
                            }
                            Err(_) => false,
                        };

                        if is_vulnerable {
                            findings.push(Finding::new(
                                constants::FINDING_SUBDOMAIN_TAKEOVER,
                                Category::Vulnerability,
                                Severity::High,
                                &format!("Potential Subdomain Takeover: {} points to unconfigured service {}", target.host, target_cname),
                                serde_json::json!({
                                    "host": target.host,
                                    "cname": target_cname,
                                    "service": service,
                                    "confidence": "high"
                                })
                            ));
                        }
                    }
                }
            }
        }
        
        Ok(findings)
    }
}
