use crate::models::{TargetHost, ScanMetadata, Severity, Finding};
use crate::core::sink::DataSink;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{info, error, debug, warn};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A DataSink that sends findings to a Discord Webhook.
///
/// V16: notifies for every severity (Info excluded — pure recon noise), not just
/// High/Critical, and accumulates everything it sees so `close()` can emit a
/// consolidated report + summary ping automatically at the end of a scan —
/// without requiring a manual "Export" click from the dashboard.
pub struct DiscordSink {
    webhook_url: String,
    proxy_manager: Arc<crate::utils::proxy::ProxyManager>,
    workspace_dir: String,
    /// (target host, finding) pairs accumulated across write() calls for the
    /// close()-time consolidated report.
    seen: Vec<(String, Finding)>,
}

impl DiscordSink {
    pub fn new(webhook_url: String, pm: Arc<crate::utils::proxy::ProxyManager>, workspace_dir: String) -> Self {
        Self {
            webhook_url,
            proxy_manager: pm,
            workspace_dir,
            seen: Vec::new(),
        }
    }

    fn get_color_for_severity(&self, severity: &Severity) -> u32 {
        match severity {
            Severity::Critical => 0xFF0000, // Red
            Severity::High => 0xFFA500,     // Orange
            Severity::Medium => 0xFFFF00,   // Yellow
            Severity::Low => 0x3498DB,      // Blue
            Severity::Info => 0x95A5A6,     // Gray
        }
    }

    /// POSTs an embed payload, logging failures instead of propagating them —
    /// one bad send must not abort notifications for the rest of the batch.
    async fn post_embed(&self, payload: serde_json::Value) {
        let host = url::Url::parse(&self.webhook_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "discord.com".to_string());

        let client = match self.proxy_manager.get_client_fail_closed(&host) {
            Ok((_, client)) => client,
            Err(e) => {
                error!("❌ DiscordSink: no se pudo construir el cliente HTTP: {}", e);
                return;
            }
        };

        match client.post(&self.webhook_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => info!("✅ DiscordSink: notificación enviada"),
            Ok(resp) => error!("❌ DiscordSink: fallo al notificar: HTTP {}", resp.status()),
            Err(e) => error!("❌ DiscordSink: error de red: {}", e),
        }
    }

    fn generate_summary_markdown(&self) -> String {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (_, f) in &self.seen {
            *counts.entry(format!("{:?}", f.core.severity)).or_insert(0) += 1;
        }

        let mut out = String::from("# Reporte de Escaneo — Mimikri RedTeam Core\n\n");
        out.push_str(&format!(
            "_Generado automáticamente al cerrar el escaneo — {}_\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        out.push_str("## Resumen por severidad\n\n");
        for (sev, count) in &counts {
            out.push_str(&format!("- **{}**: {}\n", sev, count));
        }
        out.push_str(&format!("\n**Total de hallazgos:** {}\n\n", self.seen.len()));

        out.push_str("## Detalle\n\n");
        for (host, f) in &self.seen {
            out.push_str(&format!("### [{:?}] {} — `{}`\n\n", f.core.severity, f.core.title, host));
            out.push_str(&format!("- **Categoría:** {:?}\n", f.core.category));
            out.push_str(&format!("- **Descripción:** {}\n", f.core.description));
            if let Some(ai) = &f.enrichment.ai_analysis {
                if !ai.impact.is_empty() {
                    out.push_str(&format!("- **Impacto (AI):** {}\n", ai.impact));
                }
                if !ai.exploit_path.is_empty() {
                    out.push_str(&format!("- **Exploit Path (AI):** {}\n", ai.exploit_path));
                }
            }
            out.push('\n');
        }

        out
    }
}

#[async_trait]
impl DataSink for DiscordSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        // V16: notify for every severity except Info (pure recon noise, no actionable finding).
        let notifiable: Vec<&Finding> = target.findings.iter()
            .filter(|f| f.core.severity != Severity::Info)
            .collect();

        if notifiable.is_empty() {
            return Ok(());
        }

        debug!("📢 DiscordSink: {} hallazgo(s) notificable(s) para {}", notifiable.len(), target.host);

        for finding in notifiable {
            self.seen.push((target.host.clone(), finding.clone()));

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

            self.post_embed(payload).await;
        }

        Ok(())
    }

    async fn write_metadata(&mut self, _metadata: &ScanMetadata) -> Result<()> {
        Ok(())
    }

    /// V16: fires automatically when the scan's sink pipeline shuts down — no
    /// manual "Export" click required. Writes a consolidated markdown report
    /// covering every severity level and pings Discord with a summary.
    async fn close(&mut self) -> Result<()> {
        if self.seen.is_empty() {
            return Ok(());
        }

        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (_, f) in &self.seen {
            *counts.entry(format!("{:?}", f.core.severity)).or_insert(0) += 1;
        }

        let reports_dir = std::path::PathBuf::from(&self.workspace_dir).join("reports");
        if let Err(e) = tokio::fs::create_dir_all(&reports_dir).await {
            warn!("⚠️ DiscordSink: no se pudo crear el directorio de reportes {}: {}", reports_dir.display(), e);
        }

        let filename = format!("scan_report_{}.md", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
        let report_path = reports_dir.join(&filename);
        let markdown = self.generate_summary_markdown();

        if let Err(e) = tokio::fs::write(&report_path, &markdown).await {
            error!("❌ DiscordSink: no se pudo escribir el reporte en {}: {}", report_path.display(), e);
        } else {
            info!("📝 DiscordSink: reporte de escaneo guardado automáticamente en {}", report_path.display());
        }

        let summary: String = counts.iter()
            .map(|(sev, n)| format!("**{}:** {}", sev, n))
            .collect::<Vec<_>>()
            .join(" · ");

        let payload = json!({
            "username": "Mimikri Sentinel",
            "embeds": [{
                "title": "📊 Escaneo Finalizado",
                "color": 0x2ECC71,
                "description": format!(
                    "Escaneo cerrado con **{}** hallazgo(s) en total (todas las severidades).\n\n{}\n\n📄 Reporte completo guardado en:\n`{}`",
                    self.seen.len(), summary, report_path.display()
                ),
                "footer": {
                    "text": "Mimikri Sentinel • Auto-Report on scan close"
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        self.post_embed(payload).await;

        Ok(())
    }
}
