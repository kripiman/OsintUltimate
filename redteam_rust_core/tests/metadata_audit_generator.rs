use redteam_rust_core::plugins::{get_all_scanners, get_all_discovery, GlobalConfig};
use redteam_rust_core::utils::executor::GhostMode;
use std::fs::File;
use std::io::Write;

#[tokio::test]
async fn generate_audit() {
    let config = GlobalConfig::<GhostMode>::new();
    let scanners = get_all_scanners(config.clone());
    let discoveries = get_all_discovery(config.clone());

    let mut report = String::new();
    report.push_str("# 📜 Plugin Metadata Audit Report\n\n");
    report.push_str("Este reporte documenta el estado y completitud de los metadatos para todos los plugins registrados.\n\n");
    report.push_str("## Resumen de Hallazgos\n\n");

    let total_scanners = scanners.len();
    let total_discoveries = discoveries.len();
    let total_plugins = total_scanners + total_discoveries;

    report.push_str(&format!("- **Total de plugins analizados**: {}\n", total_plugins));
    report.push_str(&format!("- **Total de Scanners**: {}\n", total_scanners));
    report.push_str(&format!("- **Total de Discovery Plugins**: {}\n\n", total_discoveries));

    report.push_str("## Auditoría Detallada de Scanners\n\n");
    report.push_str("| # | Name | Risk Level | Scan Layer | Category | Cost | Is Destructive | Poc Mode | Capabilities | Mitre Attacks |\n");
    report.push_str("|---|---|---|---|---|---|---|---|---|---|\n");

    let mut index = 1;
    let mut default_risk_count = 0;
    let mut default_layer_count = 0;
    let mut default_category_count = 0;
    let mut default_cost_count = 0;
    let mut default_destructive_count = 0;
    let mut default_poc_count = 0;
    let mut empty_capabilities_count = 0;

    for s in &scanners {
        let meta = s.metadata();
        let name = s.name();
        
        // Audit defaults
        if meta.risk_level == redteam_rust_core::plugins::RiskLevel::Medium {
            default_risk_count += 1;
        }
        if meta.layer == redteam_rust_core::core::capability_layer::ScanLayer::Scanning {
            default_layer_count += 1;
        }
        if meta.category == "General" {
            default_category_count += 1;
        }
        if meta.cost == 1 {
            default_cost_count += 1;
        }
        if !meta.is_destructive {
            default_destructive_count += 1;
        }
        if meta.poc_mode {
            default_poc_count += 1;
        }
        if meta.capabilities.is_empty() {
            empty_capabilities_count += 1;
        }

        let capabilities = format!("{:?}", meta.capabilities);
        let mitre = format!("{:?}", meta.mitre_attacks);
        report.push_str(&format!(
            "| {} | {} | {:?} | {:?} | {} | {} | {} | {} | {} | {} |\n",
            index, name, meta.risk_level, meta.layer, meta.category, meta.cost, meta.is_destructive, meta.poc_mode, capabilities, mitre
        ));
        index += 1;
    }

    report.push_str("\n## Auditoría Detallada de Discovery Plugins\n\n");
    report.push_str("| # | Name | Risk Level | Scan Layer | Category | Cost | Is Destructive | Poc Mode | Capabilities | Mitre Attacks |\n");
    report.push_str("|---|---|---|---|---|---|---|---|---|---|\n");

    for d in &discoveries {
        let meta = d.metadata();
        let name = d.name();

        // Audit defaults
        if meta.risk_level == redteam_rust_core::plugins::RiskLevel::Medium {
            default_risk_count += 1;
        }
        if meta.layer == redteam_rust_core::core::capability_layer::ScanLayer::Scanning {
            default_layer_count += 1;
        }
        if meta.category == "General" {
            default_category_count += 1;
        }
        if meta.cost == 1 {
            default_cost_count += 1;
        }
        if !meta.is_destructive {
            default_destructive_count += 1;
        }
        if meta.poc_mode {
            default_poc_count += 1;
        }
        if meta.capabilities.is_empty() {
            empty_capabilities_count += 1;
        }

        let capabilities = format!("{:?}", meta.capabilities);
        let mitre = format!("{:?}", meta.mitre_attacks);
        report.push_str(&format!(
            "| {} | {} | {:?} | {:?} | {} | {} | {} | {} | {} | {} |\n",
            index, name, meta.risk_level, meta.layer, meta.category, meta.cost, meta.is_destructive, meta.poc_mode, capabilities, mitre
        ));
        index += 1;
    }

    report.push_str("\n## Estadísticas de Valores por Defecto o Potenciales Brechas (Leakage)\n\n");
    report.push_str(&format!("- Plugins con `risk_level` en Medium (por defecto): {}\n", default_risk_count));
    report.push_str(&format!("- Plugins con `layer` en Scanning (por defecto): {}\n", default_layer_count));
    report.push_str(&format!("- Plugins con `category` en \"General\" (por defecto): {}\n", default_category_count));
    report.push_str(&format!("- Plugins con `cost` en 1 (por defecto): {}\n", default_cost_count));
    report.push_str(&format!("- Plugins con `is_destructive` en false (por defecto): {}\n", default_destructive_count));
    report.push_str(&format!("- Plugins con `poc_mode` en true (por defecto): {}\n", default_poc_count));
    report.push_str(&format!("- Plugins con `capabilities` vacíos (leakage real): {}\n", empty_capabilities_count));

    let mut file = File::create("DOCS/PLUGIN_METADATA_AUDIT.md").unwrap();
    file.write_all(report.as_bytes()).unwrap();
    println!("Report generated successfully with {} plugins.", total_plugins);
}
