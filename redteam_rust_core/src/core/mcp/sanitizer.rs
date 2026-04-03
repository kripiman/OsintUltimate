use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use regex::Regex;
use once_cell::sync::Lazy;

static IP_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b").unwrap());

pub struct DataSanitizer {
    mask_to_real: Arc<RwLock<BTreeMap<String, String>>>,
    real_to_mask: Arc<RwLock<BTreeMap<String, String>>>,
}

impl DataSanitizer {
    pub fn new() -> Self {
        Self {
            mask_to_real: Arc::new(RwLock::new(BTreeMap::new())),
            real_to_mask: Arc::new(RwLock::new(BTreeMap::new())),
        }
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
