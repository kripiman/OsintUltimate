use crate::boot::cli::Args;
use anyhow::Result;
use inquire::{Text, Confirm, MultiSelect, validator::Validation};

pub fn show_menu() -> Result<Option<Args>> {
    println!("🛡️  Bienvenido a MIMIKRI v4.0 - Unified Wizard");
    println!("=================================================\n");
    
    let target = Text::new("🎯 Introduce el objetivo (ej. example.com o targets.txt):")
        .with_help_message("Dominio base, IP o ruta local a un archivo de targets")
        .prompt()?;
        
    if target.trim().is_empty() {
        println!("❌ El objetivo no puede estar vacío.");
        return Ok(None);
    }

    let is_mobile = Confirm::new("📱 ¿Es una auditoría de aplicación móvil (APK/IPA)?")
        .with_default(false)
        .prompt()?;
    
    // Default struct parameters
    let mut args = Args {
        target: None,
        apk: None,
        image: None,
        input: None,
        jsonl_output: "scan_result.jsonl".to_string(),
        html_output: "scan_report.html".to_string(),
        postgres_url: None,
        concurrency: 10,
        scripts: None,
        stealth: false,
        service_detection: false,
        insecure: false,
        dns_servers: None,
        proxies: None,
        otel_endpoint: None,
        json_logs: false,
        plugins_dir: None,
        scan_type: "sS".to_string(),
        fragment: false,
        decoy: None,
        doh: false,
        ports: None,
        vuln_scan: false,
        autonomous: false,
        ollama_url: "http://localhost:11434".to_string(),
        max_layer: "Scanning".to_string(),
        dashboard: None,
        swarm: false,
        max_tokens: 5000,
        mcp_server: false,
        mcp_port: 3001,
        persist: false,
        consolidate: false,
        worker: false,
        node_id: None,
        nats_url: None,
        scope_id: None,
    };

    let scope_id = Text::new("🆔 Introduce el Scope ID (opcional, para aislamiento):")
        .with_help_message("Dejar vacío para el scope por defecto")
        .prompt()?;
    
    if !scope_id.trim().is_empty() {
        args.scope_id = Some(scope_id);
    }

    if is_mobile {
        args.apk = Some(target);
    } else if std::path::Path::new(&target).exists() {
        args.input = Some(target);
    } else {
        args.target = Some(target);
    }
    
    let features = vec![
        "🕵️  Discovery & OSINT (Reconocimiento pasivo/DNS)",
        "🥷  Modo Sigilo (Evasión P1/P2, Jitter real, Fragmentación)",
        "🔴 Detección de Vulnerabilidades (CVEs, NSE Vuln/Exploit)",
        "🤖 IA Autónoma (Sentinel Autopilot - Decisión en tiempo real)",
        "🚀 Modo Agresivo (Alta concurrencia, Scripts invasivos)",
        "🔱 Decepticon: Persistencia y Post-explotación (Fase 5)",
        "🛡️  Hardening & Compliance (Trivy, Kubescape, Gitleaks)",
    ];

    let selected_features = MultiSelect::new("⚙️  Selecciona las capacidades para este operativo (espacio para marcar):", features.clone())
        .with_validator(|selected: &[inquire::list_option::ListOption<&&str>]| {
            let has_stealth = selected.iter().any(|f| f.value.contains("Sigilo"));
            let has_aggressive = selected.iter().any(|f| f.value.contains("Agresivo"));
            if has_stealth && has_aggressive {
                Ok(Validation::Invalid("No puedes combinar 'Sigilo' y 'Agresivo' en una misma misión.".into()))
            } else if selected.is_empty() {
                Ok(Validation::Invalid("Debes seleccionar al menos una capacidad.".into()))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt()?;

    for feature in selected_features {
        if feature == features[0] {
            // Discovery
            args.doh = true;
            if args.max_layer == "Scanning" { args.max_layer = "Discovery".to_string(); }
        } else if feature == features[1] {
            // Stealth
            args.stealth = true;
            args.scan_type = "sS".to_string();
            args.fragment = true;
            args.concurrency = 5;
            args.doh = true;
        } else if feature == features[2] {
            // Vuln Scan
            args.vuln_scan = true;
            args.service_detection = true;
            if args.concurrency < 50 { args.concurrency = 50; }
        } else if feature == features[3] {
            // Autonomous
            args.autonomous = true;
        } else if feature == features[4] {
            // Aggressive
            args.scripts = Some("default,vuln,exploit,brute".to_string());
            args.service_detection = true;
            args.concurrency = 150;
            args.scan_type = "sT".to_string(); // TCP Connect is faster for aggressive
        } else if feature == features[5] {
            // Decepticon Persistence
            args.persist = true;
            args.consolidate = true;
            args.max_layer = "Post-exploitation".to_string();
        } else if feature == features[6] {
            // Hardening
            args.max_layer = "Verification".to_string();
        }
    }

    // Configuración de infraestructura si es necesario
    if args.stealth || Confirm::new("¿Deseas configurar proxies o DNS personalizados?").with_default(false).prompt()? {
        let use_proxies = Confirm::new("🔄 ¿Configurar Proxies rotativos (http/socks5)?")
            .with_default(args.stealth)
            .prompt()?;
            
        if use_proxies {
            let px = Text::new("   Lista de proxies (ej: socks5://127.0.0.1:9050,http://proxy:8080):")
                .prompt()?;
            if !px.trim().is_empty() {
                args.proxies = Some(px);
            }
        }
        
        if Confirm::new("🌐 ¿Configurar DNS personalizados / DoH?").with_default(args.doh).prompt()? {
            args.doh = Confirm::new("   ¿Usar DNS over HTTPS (DoH)?").with_default(args.doh).prompt()?;
            let dns = Text::new("   Servidores DNS (separados por coma, opcional):").prompt()?;
            if !dns.trim().is_empty() {
                args.dns_servers = Some(dns);
            }
        }
    }

    let mut summary = format!(
        "\n✅ Misión configurada:\n - Objetivo: {}\n",
        if is_mobile { args.apk.as_ref().unwrap() } else { args.target.as_ref().unwrap() }
    );
    summary.push_str(&format!(" - Capas: {}\n - Concurrencia: {}\n - IA Autónoma: {}\n - Sigilo: {}\n",
        args.max_layer, args.concurrency, args.autonomous, args.stealth));

    println!("{}", summary);

    if Confirm::new("🚀 ¿Iniciar operativo ahora?").with_default(true).prompt()? {
        Ok(Some(args))
    } else {
        println!("🛑 Operativo cancelado.");
        Ok(None)
    }
}
