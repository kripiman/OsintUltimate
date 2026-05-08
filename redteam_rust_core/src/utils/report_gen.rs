use crate::models::{ScanMetadata, TargetHost, Finding};
use anyhow::Result;
use handlebars::Handlebars;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;


#[derive(Serialize, Default)]
struct SummaryStats {
    total_targets: usize,
    scanned_targets: usize,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    info_count: usize,
    total_findings: usize,
    ai_summary: Option<String>,
    avg_cvss: f32,
    sca_count: usize,
}

const HTML_TEMPLATE: &str = r#"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>🛡️ Mimikri Professional Report</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <script>mermaid.initialize({ startOnLoad: true, theme: 'dark' });</script>
  <style>
    :root {
      --primary: #020617;
      --secondary: #1e293b;
      --accent: #38bdf8;
      --critical: #f43f5e;
      --high: #fb923c;
      --medium: #fbbf24;
      --low: #4ade80;
      --info: #22d3ee;
      --bg: #0b0f1a;
      --card-bg: #1e293b;
      --text: #f1f5f9;
      --muted: #94a3b8;
    }
    body { font-family: 'Outfit', 'Inter', system-ui, -apple-system, sans-serif; padding: 40px; background: var(--bg); color: var(--text); line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { margin-bottom: 40px; border-bottom: 2px solid #334155; padding-bottom: 24px; }
    h1 { font-size: 3rem; margin: 0; display: flex; align-items: center; gap: 16px; color: var(--accent); font-weight: 800; }
    .meta { font-size: 0.9375rem; color: var(--muted); margin-top: 12px; }
    
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 24px; margin-bottom: 48px; }
    .stat-card { background: var(--card-bg); padding: 24px; border-radius: 16px; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3); text-align: center; border: 1px solid #334155; transition: transform 0.2s; }
    .stat-card:hover { transform: translateY(-5px); }
    .stat-card.critical { border-top: 4px solid var(--critical); }
    .stat-card.high { border-top: 4px solid var(--high); }
    .stat-card.medium { border-top: 4px solid var(--medium); }
    .stat-value { font-size: 2.5rem; font-weight: 800; display: block; margin-bottom: 4px; }
    .stat-label { font-size: 0.8125rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); font-weight: 700; }

    .ai-executive-summary { background: rgba(56, 189, 248, 0.05); color: #f1f5f9; padding: 32px; border-radius: 20px; margin-bottom: 48px; border: 1px solid rgba(56, 189, 248, 0.2); backdrop-filter: blur(8px); }
    .ai-executive-summary h2 { margin-top: 0; color: var(--accent); font-size: 1.5rem; margin-bottom: 16px; display: flex; align-items: center; gap: 10px; }

    .attack-path { background: #020617; padding: 32px; border-radius: 20px; margin-bottom: 48px; border: 1px solid #334155; }
    .attack-path h2 { margin-top: 0; color: var(--muted); font-size: 1.25rem; margin-bottom: 24px; }

    table { width: 100%; border-collapse: separate; border-spacing: 0 12px; margin-top: 24px; }
    th { padding: 16px; text-align: left; font-size: 0.8125rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); border-bottom: 1px solid #334155; }
    td { padding: 20px; background: var(--card-bg); vertical-align: top; }
    tr td:first-child { border-radius: 12px 0 0 12px; }
    tr td:last-child { border-radius: 0 12px 12px 0; }
    
    .severity-badge { display: inline-flex; align-items: center; justify-content: center; padding: 4px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; color: #020617; }
    .severity-Critical { background: var(--critical); color: white; }
    .severity-High { background: var(--high); }
    .severity-Medium { background: var(--medium); }
    .severity-Low { background: var(--low); }
    .severity-Info { background: var(--info); }

    .cvss-badge { background: #334155; color: var(--accent); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; margin-left: 8px; border: 1px solid var(--accent); }

    .mitre-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; background: rgba(56, 189, 248, 0.1); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.2); margin-right: 6px; }

    .finding-item { margin-bottom: 16px; padding: 20px; background: rgba(15, 23, 42, 0.5); border-radius: 12px; border: 1px solid #334155; }
    .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
    .finding-description { font-size: 1rem; margin-bottom: 12px; color: #e2e8f0; }
    .finding-evidence { font-family: 'Fira Code', ui-monospace, monospace; font-size: 0.875rem; background: #020617; color: #38bdf8; padding: 16px; border-radius: 8px; margin-top: 12px; white-space: pre-wrap; word-break: break-all; border: 1px solid #1e293b; }
    
    .tactical_path-box { background: rgba(74, 222, 128, 0.05); border-left: 4px solid var(--low); padding: 16px; margin-top: 16px; border-radius: 0 8px 8px 0; font-size: 0.9375rem; }
    .tactical_path-label { font-weight: 800; color: var(--low); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 8px; display: block; }

    .references-list { margin-top: 12px; font-size: 0.8125rem; color: var(--muted); }
    .references-list a { color: var(--accent); text-decoration: none; margin-right: 12px; }
    .references-list a:hover { text-decoration: underline; }

    .ai-analysis { background: rgba(56, 189, 248, 0.08); border-left: 4px solid var(--accent); padding: 16px; margin-top: 16px; border-radius: 0 8px 8px 0; font-size: 0.9375rem; border: 1px solid rgba(56, 189, 248, 0.1); }
    .ai-label { font-weight: 800; color: var(--accent); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 8px; display: block; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ Mimikri Professional Report</h1>
      <div class="meta">
        <p><strong>Engagement Date:</strong> {{metadata.timestamp}} | <strong>Version:</strong> {{metadata.version}}</p>
        <p><strong>Scope / Execution:</strong> <code>{{metadata.command_line}}</code></p>
      </div>
    </header>

    {{#if stats.ai_summary}}
    <div class="ai-executive-summary">
      <h2>🤖 SENTINEL Executive Summary</h2>
      <p>{{stats.ai_summary}}</p>
    </div>
    <div class="summary-grid">
      <div class="stat-card">
        <span class="stat-value">{{stats.total_targets}}</span>
        <span class="stat-label">Total Assets</span>
      </div>
      <div class="stat-card critical">
        <span class="stat-value" style="color: var(--critical)">{{stats.critical_count}}</span>
        <span class="stat-label">Critical</span>
      </div>
      <div class="stat-card high">
        <span class="stat-value" style="color: var(--high)">{{stats.high_count}}</span>
        <span class="stat-label">High Risk</span>
      </div>
      <div class="stat-card">
        <span class="stat-value" style="color: var(--accent)">{{stats.avg_cvss}}</span>
        <span class="stat-label">Avg CVSS</span>
      </div>
      <div class="stat-card">
        <span class="stat-value" style="color: var(--info)">{{stats.sca_count}}</span>
        <span class="stat-label">SCA Vulns</span>
      </div>
    </div>

    {{#if mermaid_graph}}
    <div class="attack-path">
      <h2 style="color: var(--accent); border-bottom: 1px solid #334155; padding-bottom: 12px;">🕸️ Visual Attack Surface & Exposure</h2>
      <div class="mermaid">
        {{mermaid_graph}}
      </div>
    </div>
    {{/if}}

    <h2 style="font-size: 1.75rem; margin-bottom: 24px; color: var(--text);">📑 Detailed Security Findings</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 280px;">Asset / Identity</th>
          <th>Vulnerabilities & Contextual Analysis</th>
        </tr>
      </thead>
      <tbody>
        {{#each targets}}
        <tr>
          <td>
            <div style="font-weight: 800; font-size: 1.25rem; color: var(--accent);">{{host}}</div>
            <div style="color: var(--muted); font-size: 0.875rem; margin-bottom: 12px; font-family: monospace;">{{#if ip}}{{ip}}{{else}}Identity-Based{{/if}}</div>
            <span class="severity-badge severity-{{max_severity}}">{{max_severity}} Target</span>
          </td>
          <td>
            {{#if has_findings}}
              {{#each findings}}
              <div class="finding-item">
                <div class="finding-header">
                  <span class="severity-badge severity-{{core.severity}}">{{core.severity}}</span>
                  {{#if enrichment.cvss_score}}<span class="cvss-badge">CVSS {{enrichment.cvss_score}}</span>{{/if}}
                  <span style="font-weight: 700; color: #f1f5f9; text-transform: uppercase; font-size: 0.8125rem;">{{core.category}}</span>
                  {{#each enrichment.mitre_attack}}
                    <span class="mitre-badge">ATT&CK {{this}}</span>
                  {{/each}}
                </div>
                <div class="finding-description">{{core.description}}</div>
                
                {{#if enrichment.ai_analysis}}
                <div class="ai-analysis">
                  <span class="ai-label">🤖 Sentinel Autonomous Reasoning ({{enrichment.ai_analysis.model}})</span>
                  <div><strong>Summary:</strong> {{enrichment.ai_analysis.summary}}</div>
                  <div style="margin-top: 8px;"><strong>Exposure Impact:</strong> {{enrichment.ai_analysis.impact}}</div>
                  <div style="margin-top: 8px; font-style: italic; color: var(--muted); border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 8px;">Stealth Notes: {{enrichment.ai_analysis.stealth_notes}}</div>
                </div>
                {{/if}}

                {{#if evidence.tactical_path}}
                <div class="tactical_path-box">
                  <span class="tactical-label">🛠️ Technical Tactical Path</span>
                  <div>{{evidence.tactical_path}}</div>
                </div>
                {{/if}}

                {{#if enrichment.references}}
                <div class="references-list">
                  <strong>References:</strong>
                  {{#each enrichment.references}}
                    <a href="{{this}}" target="_blank">🔗 {{this}}</a>
                  {{/each}}
                </div>
                {{/if}}

                {{#if evidence.evidence.data}}
                  <details style="margin-top: 16px;">
                    <summary style="font-size: 0.75rem; color: var(--muted); cursor: pointer; text-transform: uppercase; font-weight: 700;">View Raw Evidence</summary>
                    <div class="finding-evidence">{{json_stringify evidence.evidence.data}}</div>
                  </details>
                {{/if}}
              </div>
              {{/each}}
            {{else}}
              <div style="padding: 24px; text-align: center; background: rgba(15, 23, 42, 0.3); border-radius: 12px; color: var(--muted); border: 1px dashed #334155;">
                System clean: No active vulnerabilities discovered for this asset.
              </div>
            {{/if}}
          </td>
        </tr>
        {{/each}}
      </tbody>
    </table>
  </div>
</body>
</html>
"#;


#[derive(Serialize)]
struct FullReportVM<'a> {
    metadata: &'a ScanMetadata,
    stats: SummaryStats,
    targets: Vec<TargetVM>,
    mermaid_graph: String,
}


#[derive(Serialize)]
struct TargetVM {
    host: String,
    ip: String,
    status: String,
    max_severity: String,
    has_findings: bool,
    findings: Vec<Finding>,
}


pub async fn generate_report(jsonl_path: &str, output_path: &str) -> Result<()> {
    let out_path = std::path::Path::new(output_path);
    if out_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
         anyhow::bail!("Invalid output filename: Traversal (..) detected");
    }

    let in_file = File::open(jsonl_path).await?;
    let mut reader = BufReader::new(in_file).lines();

    let mut metadata = ScanMetadata::new("Mimikri");
    let mut stats = SummaryStats::default();
    let mut targets = Vec::new();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() { continue; }
        
        let peek: serde_json::Value = serde_json::from_str(&line)?;

        if let Some(meta_val) = peek.get("metadata") {
            if let Ok(m) = serde_json::from_value(meta_val.clone()) {
                metadata = m;
                metadata.command_line = html_escape::encode_safe(&metadata.command_line).to_string();
            } else {
                tracing::warn!("Failed to parse metadata from JSONL, skipping invalid metadata line");
            }
        } else if let Ok(target) = serde_json::from_str::<TargetHost>(&line) {
            stats.total_targets += 1;
            if target.status == crate::models::TargetStatus::Scanned {
                stats.scanned_targets += 1;
            }

            let mut severity_val = 0;
            let mut severity_str = "Info";
            let mut total_cvss = 0.0;
            let mut cvss_count = 0;
            
            for f in target.findings.iter() {
                stats.total_findings += 1;
                if f.core.category == crate::models::Category::SCA {
                    stats.sca_count += 1;
                }
                if let Some(score) = f.enrichment.cvss_score {
                    total_cvss += score;
                    cvss_count += 1;
                }
                let val = match f.core.severity {
                    crate::models::Severity::Critical => { stats.critical_count += 1; 4 },
                    crate::models::Severity::High => { stats.high_count += 1; 3 },
                    crate::models::Severity::Medium => { stats.medium_count += 1; 2 },
                    crate::models::Severity::Low => { stats.low_count += 1; 1 },
                    crate::models::Severity::Info => { stats.info_count += 1; 0 },
                };
                if val > severity_val {
                    severity_val = val;
                    severity_str = match val {
                        4 => "Critical",
                        3 => "High",
                        2 => "Medium",
                        1 => "Low",
                        _ => "Info"
                    };
                }
            }

            if cvss_count > 0 {
                stats.avg_cvss = (stats.avg_cvss * (stats.total_findings as f32 - cvss_count as f32) + total_cvss) / stats.total_findings as f32;
            }

            targets.push(TargetVM {
                host: html_escape::encode_safe(&target.host).to_string(),
                ip: target.ip.clone().unwrap_or_default(),
                status: format!("{:?}", target.status),
                max_severity: severity_str.to_string(),
                has_findings: !target.findings.is_empty(),
                findings: (*target.findings).clone(),
            });
        }
    }

    let mut reg = Handlebars::new();
    reg.set_strict_mode(true);
    reg.register_helper("json_stringify", Box::new(|h: &handlebars::Helper, _: &Handlebars, _: &handlebars::Context, _: &mut handlebars::RenderContext, out: &mut dyn handlebars::Output| -> handlebars::HelperResult {
        let param = h.param(0).ok_or(handlebars::RenderError::new("Missing parameter"))?;
        out.write(&serde_json::to_string_pretty(param.value()).unwrap_or_default())?;
        Ok(())
    }));

    // Generate Mermaid Graph
    let mut mermaid = String::from("graph LR\n  Start((Start)) --> Targets[Targets]\n");
    for t in &targets {
        let host_id = t.host.replace(['.', '-'], "_");
        mermaid.push_str(&format!("  Targets --> {}\n", host_id));
        if t.has_findings {
            for (i, f) in t.findings.iter().enumerate() {
                let finding_id = format!("{}_f{}", host_id, i);
                mermaid.push_str(&format!("  {} --> {}[\"{:?}\"]\n", host_id, finding_id, f.core.category));
            }
        }
    }
    
    let vm = FullReportVM {
        metadata: &metadata,
        stats,
        targets,
        mermaid_graph: mermaid,
    };


    let rendered = reg.render_template(HTML_TEMPLATE, &vm)?;
    
    // Ensure directory exists
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    
    tokio::fs::write(out_path, rendered).await?;
    
    Ok(())
}
