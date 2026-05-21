use crate::models::{TargetHost, ScanMetadata, Severity};
use crate::core::sink::DataSink;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{info, error, debug};
use std::sync::Arc;

/// A DataSink that sends High/Critical findings to a Discord Webhook.
pub struct DiscordSink {
    webhook_url: String,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
}

impl DiscordSink {
    pub fn new(webhook_url: String, pm: Arc<crate::utils::proxy::ProxyManager>) -> Self {
        Self {
            webhook_url,
            proxy_manager: pm,
        }
    }

    fn get_color_for_severity(&self, severity: &Severity) -> u32 {
        match severity {
            Severity::Critical => 0xFF0000, // Red
            Severity::High => 0xFFA500,     // Orange
            Severity::Medium => 0xFFFF00,   // Yellow
            _ => 0x3498DB,                  // Blue (Info/Low)
        }
    }
}

#[async_trait]
impl DataSink for DiscordSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        // Find High or Critical findings
        let high_findings: Vec<_> = target.findings.iter()
            .filter(|f| f.core.severity == Severity::High || f.core.severity == Severity::Critical)
            .collect();

        if high_findings.is_empty() {
            return Ok(());
        }

        debug!("📢 DiscordSink: Found {} high-severity findings for {}", high_findings.len(), target.host);

        for finding in high_findings {
            let color = self.get_color_for_severity(&finding.core.severity);
            
            // Build the main embed
            let scrubbed_desc = crate::core::ai::scrubber::SCRUBBER.scrub(&finding.core.description);
            let mut description = format!("**Category:** {:?}\n**Description:** {}\n", 
                finding.core.category, scrubbed_desc);

            // Add AI Analysis if available
            if let Some(ai) = &finding.enrichment.ai_analysis {
                let scrubbed_impact = crate::core::ai::scrubber::SCRUBBER.scrub(&ai.impact);
                let scrubbed_path = crate::core::ai::scrubber::SCRUBBER.scrub(&ai.exploit_path);
                description.push_str("\n--- 🤖 **AI ANALYSIS** ---\n");
                description.push_str(&format!("**Impact:** {}\n", scrubbed_impact));
                description.push_str(&format!("**Exploit Path:** {}\n", scrubbed_path));
            }

            let payload = json!({
                "username": "Mimikri Sentinel",
                "avatar_url": "https://raw.githubusercontent.com/kripiman/OsintUltimate/main/mimicry_logo.png",
                "embeds": [{
                    "title": format!("🔱 Potential Vulnerability: {}", target.host),
                    "color": color,
                    "description": description,
                    "fields": [
                        {
                            "name": "🎯 Target",
                            "value": format!("`{}`", target.host),
                            "inline": true
                        },
                        {
                            "name": "⚠️ Severity",
                            "value": format!("**{:?}**", finding.core.severity),
                            "inline": true
                        },
                        {
                            "name": "👾 Agent",
                            "value": finding.context.agent,
                            "inline": true
                        }
                    ],
                    "footer": {
                        "text": "Sovereign Audit Mode • Mimikri V14.1"
                    },
                    "timestamp": chrono::Utc::now().to_rfc3339()
                }]
            });

            // Use proxy-aware client if needed, or simple reqwest
            let host = url::Url::parse(&self.webhook_url)?.host_str().unwrap_or("discord.com").to_string();
            let (_, client) = self.proxy_manager.get_client_fail_closed(&host)?;

            let res = client.post(&self.webhook_url)
                .json(&payload)
                .send()
                .await;

            match res {
                Ok(resp) if resp.status().is_success() => {
                    info!("✅ Notification sent to Discord for {}", target.host);
                }
                Ok(resp) => {
                    error!("❌ Failed to send Discord notification: HTTP {}", resp.status());
                }
                Err(e) => {
                    error!("❌ Discord network error: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn write_metadata(&mut self, _metadata: &ScanMetadata) -> Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}
