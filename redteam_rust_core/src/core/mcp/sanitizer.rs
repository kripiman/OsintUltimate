use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use regex::Regex;
use once_cell::sync::Lazy;
use crate::core::ai::scrubber::SCRUBBER;

static IP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b").unwrap());

/// Límite de seguridad para el buffer de filtrado (5MB) para evitar OOM
const MAX_FILTER_BUFFER: usize = 5 * 1024 * 1024;

/// Filtro inteligente para eliminar ruido de herramientas BlackArch
pub struct OutputFilter {
    rules: HashMap<&'static str, Vec<Regex>>,
    generic_rules: Vec<Regex>,
}

impl OutputFilter {
    pub fn new() -> Self {
        let mut rules = HashMap::new();

        // Nmap: eliminar líneas de estado y banners vacíos
        rules.insert("NmapScanner", vec![
            Regex::new(r"(?m)^SF:.*$").unwrap(),
            Regex::new(r"(?m)^Nmap done:.*$").unwrap(),
            Regex::new(r"(?m)^Service enumeration.*$").unwrap(),
        ]);

        // Nuclei: eliminar líneas [INF], [WRN] y timestamps
        rules.insert("NucleiScanner", vec![
            Regex::new(r"\[INF\]").unwrap(),
            Regex::new(r"\[WRN\]").unwrap(),
            Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").unwrap(),
        ]);

        // SQLMap: eliminar banners ASCII y barras de progreso
        rules.insert("SqlMapScanner", vec![
            Regex::new(r"(?s)___.*?___").unwrap(), // ASCII Art
            Regex::new(r"\[INFO\] testing.*").unwrap(),
            Regex::new(r"\[\d+%\]").unwrap(),
        ]);

        // Feroxbuster: eliminar líneas 404/403 masivas
        rules.insert("FeroxbusterScanner", vec![
            Regex::new(r"(?m)^.*404.*$").unwrap(),
            Regex::new(r"(?m)^.*403.*$").unwrap(),
        ]);

        // Reglas Genéricas para cualquier herramienta BlackArch (Fallback)
        let generic_rules = vec![
            Regex::new(r"(?m)^.*\[[#= ]+\] [0-9]+%.*$").unwrap(), // Progress bars
            Regex::new(r"(?m)^.*\[[ \.]*\] [0-9]+%.*$").unwrap(), // Progress dots
            Regex::new(r"(?mi)^.*(copyright|license|all rights reserved).*$").unwrap(), // Boilerplate
            Regex::new(r"(?m)^[.=_\-]{10,}$").unwrap(), // Visual separators
        ];

        Self { rules, generic_rules }
    }

    pub fn filter(&self, plugin_name: &str, output: &str) -> String {
        // Hardening: Si el output es excesivo, truncar preventivamente
        let input = if output.len() > MAX_FILTER_BUFFER {
            tracing::warn!("🛡️ [MCP-HARDEN] Truncando output de {} por exceso de tamaño ({} bytes)", 
                plugin_name, output.len());
            &output[..MAX_FILTER_BUFFER]
        } else {
            output
        };

        let mut lines: Vec<String> = input.lines().map(|s| s.to_string()).collect();
        
        // 1. Aplicar reglas específicas o genéricas
        let active_rules = self.rules.get(plugin_name).unwrap_or(&self.generic_rules);
        
        // Procesamiento en una sola pasada de líneas para eficiencia (Streaming-like)
        lines.retain(|line| {
            if line.trim().is_empty() { return false; }
            for re in active_rules {
                if re.is_match(line) { return false; }
            }
            true
        });

        // 2. Limpieza final de ruido en las líneas restantes
        lines.join("\n")
    }
}

pub struct DataSanitizer {
    mask_to_real: Arc<RwLock<BTreeMap<String, String>>>,
    real_to_mask: Arc<RwLock<BTreeMap<String, String>>>,
    filter: OutputFilter,
}

impl DataSanitizer {
    pub fn new() -> Self {
        Self {
            mask_to_real: Arc::new(RwLock::new(BTreeMap::new())),
            real_to_mask: Arc::new(RwLock::new(BTreeMap::new())),
            filter: OutputFilter::new(),
        }
    }

    /// Filtra ruido, aplica scrubbing de credenciales y enmascara IPs/Dominios
    pub fn filter_tool_output(&self, plugin_name: &str, text: &str) -> String {
        // FAIL-CLOSED DESIGN: Si el input está vacío o es nulo, retornar vacío seguro
        if text.trim().is_empty() {
            return String::new();
        }

        // 1. Filtrado semántico (BlackArch rules) con OOM Protection
        let filtered = self.filter.filter(plugin_name, text);
        
        // 2. Anti-alucinación: Scrubbing de credenciales/tokens
        let scrubbed = SCRUBBER.scrub(&filtered);

        // 3. Verificación de Integridad: Si el scrubbing falló (retornó vacío por error interno)
        // pero el input tenía datos, usar un placeholder seguro.
        if scrubbed.is_empty() && !filtered.is_empty() {
            tracing::error!("🚨 [MCP-HARDEN] Error crítico en pipeline de filtrado para {}. Activando Fail-Closed.", plugin_name);
            return "[ERROR: FILTRADO_DE_SEGURIDAD_FALLIDO]".to_string();
        }

        scrubbed
    }

    /// Enmascara IPs y Dominios en un texto de salida (Osint -> IA)
    pub fn mask_output(&self, text: &str) -> String {
        let mut masked = text.to_string();
        
        // 1. Enmascarar IPs
        for cap in IP_RE.find_iter(text) {
            let real = cap.as_str();
            let mask = self.get_or_create_mask(real, "IP_TARGET");
            masked = masked.replace(real, &mask);
        }

        // 2. Enmascarar Dominios
        for cap in DOMAIN_RE.find_iter(text) {
            let real = cap.as_str();
            // Evitar enmascarar localhost o dominios comunes si fuera necesario
            if real == "127.0.0.1" || real == "localhost" { continue; }
            let mask = self.get_or_create_mask(real, "DOMAIN_TARGET");
            masked = masked.replace(real, &mask);
        }

        masked
    }

    /// Des-enmascara la entrada de la IA hacia el motor real (IA -> Osint)
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
    fn test_generic_fallback_filter() {
        let sanitizer = DataSanitizer::new();
        let noise = "
[##########] 50%
Copyright (c) 2026 Offensive Security
------------------------------
Real data here
        ";
        
        // Simular una herramienta desconocida
        let filtered = sanitizer.filter_tool_output("UnknownTool", noise);
        
        assert!(!filtered.contains("50%"));
        assert!(!filtered.contains("Copyright"));
        assert!(!filtered.contains("-----"));
        assert!(filtered.contains("Real data here"));
    }

    #[test]
    fn test_specific_nmap_filter() {
        let sanitizer = DataSanitizer::new();
        let nmap_output = "SF: Port 80 is open\nNmap done: 1 host up\nActual Result";
        let filtered = sanitizer.filter_tool_output("NmapScanner", nmap_output);
        
        assert!(!filtered.contains("SF:"));
        assert!(!filtered.contains("Nmap done"));
        assert!(filtered.contains("Actual Result"));
    }
}
