use crate::Args;
use anyhow::Result;
use inquire::{Select, Text, Confirm};

pub fn show_menu() -> Result<Option<Args>> {
    println!("🛡️  Bienvenido a OsintUltimate v3.0 - Interactive Setup");
    println!("====================================================\n");
    
    let target = Text::new("🎯 Introduce el objetivo (ej. example.com):")
        .with_help_message("Domínio base, IP o ruta local a un archivo de targets")
        .prompt()?;
        
    if target.trim().is_empty() {
        println!("❌ El objetivo no puede estar vacío.");
        return Ok(None);
    }
    
    // Default struct parameters corresponding to the CLI defaults
    let mut args = Args {
        target: None,
        input: None,
        jsonl_output: "scan_result.jsonl".to_string(),
        html_output: "scan_report.html".to_string(),
        sqlite_output: None,
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
    };

    if std::path::Path::new(&target).exists() {
        args.input = Some(target.clone());
    } else {
        args.target = Some(target.clone());
    }
    
    let options = vec![
        "1. Discovery Only (OSINT, Zero Noise)",
        "2. Stealth Audit (Low & Slow, Evasion P1/P2)",
        "3. Aggressive Full Surface (All Scripts, High Concurrency)",
        "4. \u{1F534} Vulnerability Hunter (Max CVE Detection)",
        "5. Custom Configuration"
    ];
    
    let profile = Select::new("⚙️  Selecciona el Perfil de Escaneo (Playbook):", options.clone()).prompt()?;

    if profile == options[0] {
        // Discovery Only
        args.doh = true;
    } else if profile == options[1] {
        // Stealth Audit
        args.stealth = true;
        args.scan_type = "sS".to_string();
        args.fragment = true;
        args.concurrency = 5;
        args.doh = true;
        
        let use_proxies = Confirm::new("🔄 ¿Deseas configurar Proxies rotativos (Recomendado para Stealth)?")
            .with_default(false)
            .prompt()?;
            
        if use_proxies {
            let px = Text::new("   Lista de proxies (http/socks5) separados por coma:")
                .with_help_message("ej: socks5://127.0.0.1:9050,http://proxy:8080")
                .prompt()?;
            if !px.trim().is_empty() {
                args.proxies = Some(px);
            }
        }
    } else if profile == options[2] {
        // Aggressive
        args.scripts = Some("default,vuln,exploit".to_string());
        args.service_detection = true;
        args.concurrency = 150;
    } else if profile == options[3] {
        // 🔴 Vulnerability Hunter — professional CVE hunting profile
        args.vuln_scan = true;
        args.service_detection = true;
        args.concurrency = 50;
        println!("\n  🔴 Vulnerability Hunter activado:");
        println!("     • OS Detection (-O --osscan-guess)");
        println!("     • Version Intensity 9 (-sV --version-intensity 9)");
        println!("     • NSE Suite: vuln, exploit, auth, default, discovery");
        println!("     • Top 5000 ports · Script timeout: 10min · Host timeout: 24h\n");
    } else {
        // Custom Configuration
        args.stealth = Confirm::new("¿Habilitar Modo Sigiloso (Jitter, Profiling ligero)?")
            .with_default(false)
            .prompt()?;
            
        args.doh = Confirm::new("¿Usar DNS over HTTPS (DoH) para privacidad?")
            .with_default(true)
            .prompt()?;
            
        args.service_detection = Confirm::new("¿Habilitar Detección de Servicios y Versiones de Nmap (-sV)?")
            .with_default(false)
            .prompt()?;
            
        let custom_scripts = Text::new("Ejecutar Scripts Nmap (NSE) - separado por comas (vacío = ninguno):")
            .with_help_message("ej: http-title,vuln,auth")
            .prompt()?;
            
        if !custom_scripts.trim().is_empty() {
             args.scripts = Some(custom_scripts);
        }

        let custom_ports = Text::new("Puertos a escanear (vacío = top 3000):")
            .with_help_message("ej: 1-65535, 80,443,8080, o vacío para top-ports")
            .prompt()?;
            
        if !custom_ports.trim().is_empty() {
             args.ports = Some(custom_ports);
        }
        
        let conc_str = Text::new("Nivel de Concurrencia (Máximos hilos paralelos):")
             .with_default("10")
             .prompt()?;
        args.concurrency = conc_str.parse().unwrap_or(10);
    }
    
    println!("\n✅ Perfil configurado para objetivo '{}' correctamente. Iniciando motor...\n", target);

    Ok(Some(args))
}
