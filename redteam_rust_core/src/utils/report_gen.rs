use crate::models::{ScanResult, Finding};
use anyhow::Result;
use handlebars::Handlebars;
use serde::Serialize;
use std::fs;

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
    <tbody>
      {{#each targets}}
      <tr>
        <td style="font-weight: 500;">{{host}} <div style="font-size:11px;color:#64748b">{{ip}}</div></td>
        <td>
           {{{status_html}}}
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
                </li>
                {{/each}}
            </ul>
            {{else}}
            <span style="color:#94a3b8;font-style:italic;">No findings</span>
            {{/if}}
        </td>
      </tr>
      {{/each}}
    </tbody>
  </table>
</body>
</html>
"#;

#[derive(Serialize)]
struct ReportVM<'a> {
    metadata: &'a crate::models::ScanMetadata,
    targets: Vec<TargetVM>,
}

#[derive(Serialize)]
struct TargetVM {
    host: String,
    ip: String,
    status_html: String,
    max_severity: String,
    has_findings: bool,
    findings: Vec<Finding>,
}

pub fn generate_report(result: &ScanResult, output_path: &str) -> Result<()> {
    let mut targets_vm = Vec::new();

    for target in &result.targets {
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

        let status_html = if target.status == "alive" {
            "<span style='color:green;font-weight:bold;'>Alive</span>".to_string()
        } else {
            format!("<span style='color:red;'>{}</span>", target.status)
        };

        targets_vm.push(TargetVM {
            host: target.host.clone(),
            ip: target.ip.clone().unwrap_or_default(),
            status_html,
            max_severity: severity_str.to_string(),
            has_findings: !target.findings.is_empty(),
            findings: target.findings.clone(),
        });
    }

    let vm = ReportVM {
        metadata: &result.metadata,
        targets: targets_vm,
    };

    let reg = Handlebars::new();
    let html = reg.render_template(HTML_TEMPLATE, &vm)?;
    fs::write(output_path, html)?;
    
    Ok(())
}
