use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use regex::Regex;
use once_cell::sync::Lazy;
use crate::core::ai::scrubber::SCRUBBER;

static IP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b").unwrap());

/// Filtro inteligente para eliminar ruido de herramientas BlackArch
pub struct OutputFilter {
    rules: HashMap<&'static str, Vec<Regex>>,
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

        Self { rules }
    }

    pub fn filter(&self, plugin_name: &str, output: &str) -> String {
        let mut filtered = output.to_string();
        if let Some(tool_rules) = self.rules.get(plugin_name) {
            for re in tool_rules {
                filtered = re.replace_all(&filtered, "").to_string();
            }
        }
        
        // Limpieza de líneas vacías sobrantes
        filtered.lines()
            .filter(|l| !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n")
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
        // 1. Filtrado semántico (BlackArch rules)
        let filtered = self.filter.filter(plugin_name, text);
        
        // 2. Anti-alucinación: Scrubbing de credenciales/tokens
        SCRUBBER.scrub(&filtered)
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
