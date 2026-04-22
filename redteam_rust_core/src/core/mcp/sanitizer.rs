use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use regex::Regex;
use once_cell::sync::Lazy;
use crate::core::ai::scrubber::SCRUBBER;

static IP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b").unwrap()
});

const MAX_FILTER_BUFFER: usize = 5 * 1024 * 1024;

// SQLMap allowlist: solo conservar líneas que contengan señal real de explotación.
// El log de SQLMap mezcla [INFO] de ruido con [INFO] de señal — la distinción es el contenido.
static SQLMAP_SIGNAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(injectable|injection|payload|parameter .* appears|retrieved|fetching|DBMS|database:|table:|column:|back-end DBMS|vulnerable|sqlmap identified|available databases|current database|current user|hostname)"
    ).unwrap()
});

// Feroxbuster --quiet output: "200      GET   1234l   5678w  123456c http://..."
// Conservar solo líneas con código HTTP 2xx/3xx al inicio de línea (señal).
// Eliminar 4xx/5xx que son ruido masivo en fuzzing.
static FEROX_NOISE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(?:4\d{2}|5\d{2})\s+").unwrap()
});

// Naabu sin -silent puede emitir el banner del motor Go de ProjectDiscovery.
static NAABU_NOISE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:naabu|projectdiscovery|current naabu version|running .* scan|use sudo|INF\]|WRN\]|ERR\])").unwrap()
});

// Httpx sin -silent emite líneas de estado del motor antes de los resultados.
static HTTPX_NOISE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:httpx|projectdiscovery|current httpx version|\[INF\]|\[WRN\]|\[ERR\]|Use with caution)").unwrap()
});

// TruffleHog sin --json emite progress/banners antes de los hallazgos.
static TRUFFLEHOG_NOISE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:trufflehog|scanning\.\.\.|progress:|chunks:|🐷|🔑|Found verified|Found unverified result that is [^:]+$)").unwrap()
});

// Reglas genéricas aplicadas SIEMPRE (acumulativas con las específicas).
static GENERIC_NOISE_RULES: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Barras de progreso: [####] 50% / [....] 23%
        Regex::new(r"^\s*\[[\s#=\.]+\]\s*\d+%").unwrap(),
        // Separadores visuales puros: ===, ---, +++, ___
        Regex::new(r"^[\s=\-_+]{10,}$").unwrap(),
        // Boilerplate legal
        Regex::new(r"(?i)^\s*(?:copyright|all rights reserved|license|this tool is for)").unwrap(),
    ]
});

/// Estrategia de filtrado por plugin.
enum FilterStrategy {
    /// Denylist: eliminar líneas que matcheen los regex.
    Deny(Vec<&'static Lazy<Regex>>),
    /// Allowlist: conservar solo líneas que matcheen el regex de señal.
    Allow(&'static Lazy<Regex>),
}

pub struct OutputFilter {
    strategies: HashMap<&'static str, FilterStrategy>,
}

impl Default for OutputFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFilter {
    pub fn new() -> Self {
        let mut strategies = HashMap::new();

        // Feroxbuster: eliminar 4xx/5xx. El resto (2xx/3xx) es señal.
        strategies.insert(
            "FeroxbusterScanner",
            FilterStrategy::Deny(vec![&FEROX_NOISE_RE]),
        );

        // Naabu: eliminar líneas de banner/motor Go-PD. Conservar "host:port".
        strategies.insert(
            "NaabuScanner",
            FilterStrategy::Deny(vec![&NAABU_NOISE_RE]),
        );

        // Httpx: eliminar líneas de motor. Conservar líneas de resultado.
        strategies.insert(
            "HttpxScanner",
            FilterStrategy::Deny(vec![&HTTPX_NOISE_RE]),
        );

        // TruffleHog: eliminar progress/banners. Conservar líneas de hallazgo.
        strategies.insert(
            "TruffleHogScanner",
            FilterStrategy::Deny(vec![&TRUFFLEHOG_NOISE_RE]),
        );

        // SQLMap: allowlist — el log mezcla ruido e información crítica en el mismo
        // prefijo [INFO]. Solo conservar líneas con términos de explotación confirmada.
        strategies.insert(
            "SqlMapScanner",
            FilterStrategy::Allow(&SQLMAP_SIGNAL_RE),
        );

        Self { strategies }
    }

    pub fn filter(&self, plugin_name: &str, output: &str) -> String {
        let input = if output.len() > MAX_FILTER_BUFFER {
            tracing::warn!(
                "🛡️ [MCP-HARDEN] Truncando output de {} ({} bytes > 5MB)",
                plugin_name, output.len()
            );
            &output[..MAX_FILTER_BUFFER]
        } else {
            output
        };

        let lines: Vec<&str> = input.lines().collect();

        let filtered: Vec<&str> = match self.strategies.get(plugin_name) {
            Some(FilterStrategy::Allow(signal_re)) => {
                // Allowlist: conservar solo líneas con señal real.
                // Las genéricas no aplican aquí — en SQLMap un separador visual
                // puede estar pegado a una línea de señal.
                lines.into_iter()
                    .filter(|line| {
                        let t = line.trim();
                        !t.is_empty() && signal_re.is_match(t)
                    })
                    .collect()
            }
            Some(FilterStrategy::Deny(deny_rules)) => {
                // Denylist específica + genéricas acumulativas.
                lines.into_iter()
                    .filter(|line| {
                        let t = line.trim();
                        if t.is_empty() { return false; }
                        // 1. Reglas genéricas siempre (GAP-5: Guard for code indentation)
                        let is_code = t.contains("fn ") || t.contains("def ") || t.contains("pub ") || t.contains("let ") || t.contains("mut ");
                        
                        for re in GENERIC_NOISE_RULES.iter() {
                            // If it looks like code, don't apply rules that might strip indentation
                            if is_code && re.as_str().contains(r"^\s*") { continue; }
                            
                            if re.is_match(t) { return false; }
                        }
                        // 2. Reglas específicas del plugin
                        for re in deny_rules {
                            if re.is_match(t) { return false; }
                        }
                        true
                    })
                    .collect()
            }
            None => {
                // Plugin sin reglas específicas: solo genéricas.
                lines.into_iter()
                    .filter(|line| {
                        let t = line.trim();
                        if t.is_empty() { return false; }
                        
                        let is_code = t.contains("fn ") || t.contains("def ") || t.contains("pub ") || t.contains("let ") || t.contains("mut ");

                        for re in GENERIC_NOISE_RULES.iter() {
                            if is_code && re.as_str().contains(r"^\s*") { continue; }
                            
                            if re.is_match(t) { return false; }
                        }
                        true
                    })
                    .collect()
            }
        };

        filtered.join("\n")
    }

    /// GAP-8: File type detection.
    /// Clasifica el contenido como código o lenguaje natural.
    pub fn is_compressible_file(path: &str) -> bool {
        matches!(
            std::path::Path::new(path).extension().and_then(|e| e.to_str()),
            Some("md") | Some("txt") | Some("markdown") | Some("log") | None
        )
    }

    pub fn is_code_file(path: &str) -> bool {
        matches!(
            std::path::Path::new(path).extension().and_then(|e| e.to_str()),
            Some("rs") | Some("py") | Some("js") | Some("ts") | Some("go") | Some("c") | Some("cpp")
        )
    }
}

pub struct DataSanitizer {
    mask_to_real: Arc<RwLock<BTreeMap<String, String>>>,
    real_to_mask: Arc<RwLock<BTreeMap<String, String>>>,
    filter: OutputFilter,
}

impl Default for DataSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl DataSanitizer {
    pub fn new() -> Self {
        Self {
            mask_to_real: Arc::new(RwLock::new(BTreeMap::new())),
            real_to_mask: Arc::new(RwLock::new(BTreeMap::new())),
            filter: OutputFilter::new(),
        }
    }

    /// Pipeline: filtrado semántico → scrubbing de secretos → fail-closed.
    pub fn filter_tool_output(&self, plugin_name: &str, text: &str) -> String {
        if text.trim().is_empty() {
            return String::new();
        }

        let filtered = self.filter.filter(plugin_name, text);

        let scrubbed = SCRUBBER.scrub(&filtered);

        if scrubbed.is_empty() && !filtered.is_empty() {
            tracing::error!(
                "🚨 [MCP-HARDEN] Pipeline de filtrado falló para {}. Activando Fail-Closed.",
                plugin_name
            );
            return "[ERROR: FILTRADO_DE_SEGURIDAD_FALLIDO]".to_string();
        }

        scrubbed
    }

    /// Enmascara IPs y dominios en el output hacia la IA.
    pub fn mask_output(&self, text: &str) -> String {
        let mut masked = text.to_string();

        for cap in IP_RE.find_iter(text) {
            let real = cap.as_str();
            let mask = self.get_or_create_mask(real, "IP_TARGET");
            masked = masked.replace(real, &mask);
        }

        for cap in DOMAIN_RE.find_iter(text) {
            let real = cap.as_str();
            if real == "127.0.0.1" || real == "localhost" { continue; }
            let mask = self.get_or_create_mask(real, "DOMAIN_TARGET");
            masked = masked.replace(real, &mask);
        }

        masked
    }

    /// Des-enmascara la entrada de la IA hacia el motor real.
    pub fn unmask_input(&self, text: &str) -> String {
        let mut real_text = text.to_string();
        let mapping = self.mask_to_real.read().unwrap();
        for (mask, real) in mapping.iter() {
            real_text = real_text.replace(mask, real);
        }
        real_text
    }

    fn get_or_create_mask(&self, real: &str, prefix: &str) -> String {
        {
            let r2m = self.real_to_mask.read().unwrap();
            if let Some(mask) = r2m.get(real) {
                return mask.clone();
            }
        }
        let mut r2m = self.real_to_mask.write().unwrap();
        let mut m2r = self.mask_to_real.write().unwrap();
        let count = r2m.len() + 1;
        let mask = format!("{}_{}", prefix, count);
        r2m.insert(real.to_string(), mask.clone());
        m2r.insert(mask.clone(), real.to_string());
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feroxbuster_keeps_2xx_drops_4xx() {
        let s = DataSanitizer::new();
        let input = "200      GET   1234l   5678w  http://target.com/admin\n\
                     404      GET      0l      0w  http://target.com/missing\n\
                     301      GET      0l      0w  http://target.com/old";
        let out = s.filter_tool_output("FeroxbusterScanner", input);
        assert!(out.contains("200"), "debe conservar 200");
        assert!(out.contains("301"), "debe conservar 301");
        assert!(!out.contains("404"), "debe eliminar 404");
    }

    #[test]
    fn test_feroxbuster_keeps_path_with_404_in_url() {
        // Un path que contiene "404" en la URL no debe eliminarse si el status es 200
        let s = DataSanitizer::new();
        let input = "200      GET   100l   200w  http://target.com/error404handler";
        let out = s.filter_tool_output("FeroxbusterScanner", input);
        assert!(out.contains("error404handler"), "no debe eliminar URL con 404 en el path");
    }

    #[test]
    fn test_naabu_drops_banner_keeps_ports() {
        let s = DataSanitizer::new();
        let input = "[INF] Current naabu version v2.3.0\n\
                     [INF] Running SYN scan with root privileges\n\
                     192.168.1.1:80\n\
                     192.168.1.1:443\n\
                     [INF] Found 2 ports";
        let out = s.filter_tool_output("NaabuScanner", input);
        assert!(!out.contains("[INF]"), "debe eliminar líneas INF");
        assert!(out.contains(":80"), "debe conservar host:port");
        assert!(out.contains(":443"), "debe conservar host:port");
    }

    #[test]
    fn test_sqlmap_allowlist_keeps_signal_drops_noise() {
        let s = DataSanitizer::new();
        let input = "[INFO] testing connection to the target URL\n\
                     [INFO] checking if the target is protected by some kind of WAF/IPS\n\
                     [WARNING] GET parameter 'id' appears to be 'AND boolean-based blind' injectable\n\
                     [INFO] fetching database names\n\
                     [INFO] retrieved: users_db\n\
                     [INFO] testing for SQL injection on GET parameter 'name'";
        let out = s.filter_tool_output("SqlMapScanner", input);
        assert!(out.contains("injectable"), "debe conservar señal de inyección");
        assert!(out.contains("fetching"), "debe conservar fetching");
        assert!(out.contains("retrieved"), "debe conservar retrieved");
        assert!(!out.contains("testing connection"), "debe eliminar ruido de conexión");
        assert!(!out.contains("WAF/IPS"), "debe eliminar ruido de WAF check");
    }

    #[test]
    fn test_generic_rules_always_apply() {
        let s = DataSanitizer::new();
        // Plugin sin reglas específicas — solo genéricas
        let input = "[##########] 50%\n\
                     Copyright (c) 2026 Tool Author\n\
                     ====================\n\
                     real finding here";
        let out = s.filter_tool_output("UnknownTool", input);
        assert!(!out.contains("50%"));
        assert!(!out.contains("Copyright"));
        assert!(!out.contains("===="));
        assert!(out.contains("real finding here"));
    }

    #[test]
    fn test_generic_rules_accumulate_with_specific() {
        // Feroxbuster tiene reglas específicas — las genéricas también deben aplicar
        let s = DataSanitizer::new();
        let input = "200      GET   100l   200w  http://target.com/admin\n\
                     [##########] 50%\n\
                     ====================";
        let out = s.filter_tool_output("FeroxbusterScanner", input);
        assert!(out.contains("200"), "señal debe pasar");
        assert!(!out.contains("50%"), "genérica debe eliminar progress bar");
        assert!(!out.contains("===="), "genérica debe eliminar separador");
    }
}
