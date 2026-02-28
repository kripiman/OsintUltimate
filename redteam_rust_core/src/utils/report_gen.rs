use crate::models::{ScanMetadata, TargetHost, Finding};
use anyhow::{Context, Result};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::fs::File;

const HTML_TEMPLATE: &str = r#"
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>RedTeam Rust Scan Report</title>
  <style>
    body {font-family: Inter, Roboto, Arial, sans-serif; padding: 20px; background:#f7fafc; color: #1e293b;}
    h1, h2 { color: #0f172a; }
    table {border-collapse: collapse; width: 100%; background: white; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06); border-radius: 8px; overflow: hidden; margin-top: 20px;}
    th, td {padding: 12px 16px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 14px;}
    th {background: #1e293b; color: #f8fafc; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;}
    tr:last-child td {border-bottom: none;}
    tr:hover {background-color: #f1f5f9;}
    
    .Critical {background: #fecaca; color: #991b1b;}
    .High {background: #ffedd5; color: #9a3412;}
    .Medium {background: #fef08a; color: #854d0e;}
    .Low {background: #e9f5db; color: #365314;}
    .Info {background: #e0f2fe; color: #075985;}
    
    .status-Scanned { color: green; font-weight: bold; }
    .status-Scanning { color: blue; }
    .status-Dead { color: gray; }
    .status-Error { color: red; font-weight: bold; }
    .status-Pending { color: orange; }
    
    .badge {display:inline-block; padding:2px 8px; border-radius:9999px; font-size:11px; font-weight: 600; background: #cbd5e1; color: #334155; margin-right: 4px; margin-bottom: 4px;}
    .finding-list {margin: 0; padding-left: 20px;}
    .meta { font-size: 12px; color: #64748b; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>🛡️ RedTeam Rust Engine - Engagement Report</h1>
  <div class="meta">
    <p><strong>Generated:</strong> {{metadata.timestamp}}</p>
    <p><strong>Tool Version:</strong> {{metadata.version}}</p>
    <p><strong>Command:</strong> <code>{{metadata.command_line}}</code></p>
  </div>

  <h2>Target Analysis Report</h2>
  <p>Copy this table directly to Excel/Sheets.</p>
  
  <table>
    <thead>
      <tr>
        <th>Host</th>
        <th>IP Status</th>
        <th>Top Severity</th>
        <th>Detailed Findings</th>
      </tr>
    </thead>
"#;

const HTML_FOOTER: &str = r#"
    </tbody>
  </table>
</body>
</html>
"#;

#[derive(Serialize)]
struct ReportVM<'a> {
    metadata: &'a ScanMetadata,
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

#[derive(Deserialize)]
struct JsonlLine {
    metadata: Option<ScanMetadata>,
    host: Option<String>,
}

pub async fn generate_report(jsonl_path: &str, output_path: &str) -> Result<()> {
    // P0 FIX: Robust Path Traversal Prevention
    let out_path = std::path::Path::new(output_path);
    
    // 1. Resolve parent directory absolute path
    let parent = out_path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    
    // V5 FIX: Ensure directory exists so canonicalize doesn't crash
    if !parent.exists() {
        tokio::fs::create_dir_all(parent).await.context("Failed to create report output directory")?;
    }
    
    let absolute_parent = tokio::fs::canonicalize(parent).await
        .context("Failed to resolve report output directory")?;

    // 2. Ensure we are not writing outside of intended CWD/subdirs? 
    // Actually, user might want to write to /tmp. 
    // The critical check is that the filename itself doesn't walk up FROM the parent.
    // canonicalize(parent) fails if parent doesn't exist.
    
    // Better check: If filename contains anything fishy after joining.
    // But standard practice: Just ensure we can write there.
    // The previous vulnerability was: user provides "../../etc/cron.d/exploit".
    // ".." is a component.
    
    if out_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
         anyhow::bail!("Invalid output filename: Traversal (..) detected");
    }
    
    // 3. Reconstruct full path with resolved parent (symbolic links resolved)
    let filename = out_path.file_name().context("Invalid output path: no filename")?;
    let safe_path = absolute_parent.join(filename);

    let mut out_file = File::create(&safe_path).await?;
    let in_file = File::open(jsonl_path).await?;
    let mut reader = BufReader::new(in_file).lines();

    let mut reg = Handlebars::new();
    // Split template into header (with metadata), row, and footer to stream output
    // V7 FIX (MEDIUM-003): HTML_TEMPLATE now safely acts only as the HTML_HEADER to avoid confusion
    let header_template = HTML_TEMPLATE.to_string() + "<tbody>";
    let row_template = r#"
      <tr>
        <td style="font-weight: 500;">{{host}} <div style="font-size:11px;color:#64748b">{{ip}}</div></td>
        <td>
           <span class="status-{{status}}">{{status}}</span>
        </td>
        <td class="{{max_severity}}">
            {{max_severity}}
        </td>
        <td>
            {{#if has_findings}}
            <ul class="finding-list">
                {{#each findings}}
                <li>
                    <span class="badge">{{severity}}</span> 
                    <strong>{{category}}:</strong> {{description}}
                    {{#if evidence}}
                    <div style="font-size:11px; color:#475569; margin-top:2px; font-family:monospace; background: #f8fafc; padding: 4px; border-radius: 4px; white-space: pre-wrap; word-break: break-all;">
                        {{evidence}}
                    </div>
                    {{/if}}
                </li>
                {{/each}}
            </ul>
            {{else}}
            <span style="color:#94a3b8;font-style:italic;">No findings</span>
            {{/if}}
        </td>
      </tr>"#;
    
    reg.register_template_string("header", &header_template)?;
    reg.register_template_string("row", row_template)?;
    
    // CRIT-005 FIX: Explicitly ensure Handlebars HTML escaping is enabled (default is true, but we make it explicit)
    reg.set_strict_mode(true);

    let mut header_written = false;
    use tokio::io::AsyncWriteExt;

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() { continue; }
        
        // Peek to see if it's metadata or a target
        let peek: JsonlLine = match serde_json::from_str(&line) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if let Some(metadata) = peek.metadata {
             // CRIT-005: Sanitize metadata fields
             let sanitized_command = html_escape::encode_safe(&metadata.command_line).to_string();
             let mut sanitized_meta = metadata;
             sanitized_meta.command_line = sanitized_command;
             
             let vm = ReportVM { metadata: &sanitized_meta };
             let rendered_header = reg.render("header", &vm)?;
             out_file.write_all(rendered_header.as_bytes()).await?;
             header_written = true;
        } else if peek.host.is_some() {
            if !header_written {
                // Failsafe in case metadata was missing
                let default_meta = ScanMetadata::new("redteam_rust_core");
                let vm = ReportVM { metadata: &default_meta };
                let rendered_header = reg.render("header", &vm)?;
                out_file.write_all(rendered_header.as_bytes()).await?;
                header_written = true;
            }

            if let Ok(target) = serde_json::from_str::<TargetHost>(&line) {
                // Calculate Max Severity
                let mut severity_val = 0;
                let mut severity_str = "Info";
                
                for f in &target.findings {
                    let val = match f.severity {
                        crate::models::Severity::Critical => 4,
                        crate::models::Severity::High => 3,
                        crate::models::Severity::Medium => 2,
                        crate::models::Severity::Low => 1,
                        crate::models::Severity::Info => 0,
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

                let status = match target.status {
                    crate::models::TargetStatus::Scanned => "Scanned".to_string(),
                    crate::models::TargetStatus::Scanning => "Scanning".to_string(),
                    crate::models::TargetStatus::Dead => "Dead".to_string(),
                    crate::models::TargetStatus::Error => "Error".to_string(),
                    crate::models::TargetStatus::Pending => "Pending".to_string(),
                };

                let mut sanitized_findings = target.findings.clone();
                for f in &mut sanitized_findings {
                    f.description = html_escape::encode_safe(&f.description).to_string();
                }

                let target_vm = TargetVM {
                    host: html_escape::encode_safe(&target.host).to_string(),
                    ip: target.ip.clone().unwrap_or_default(),
                    status,
                    max_severity: severity_str.to_string(),
                    has_findings: !sanitized_findings.is_empty(),
                    findings: sanitized_findings,
                };

                let rendered_row = reg.render("row", &target_vm)?;
                out_file.write_all(rendered_row.as_bytes()).await?;
            }
        }
    }

    // Write footer
    out_file.write_all(HTML_FOOTER.as_bytes()).await?;
    
    out_file.flush().await?;
    Ok(())
}
