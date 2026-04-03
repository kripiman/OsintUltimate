use sysinfo::System;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use crate::core::blackarch::ResourceCost;

#[derive(Clone)]
pub struct SysResourceManager {
    sys: Arc<Mutex<System>>,
    pub total_ram_mb: u64,
    pub strict_threshold_mb: u64, 
}

impl SysResourceManager {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_memory();
        // sysinfo 0.30+ uses bytes exclusively
        let total_ram_mb = sys.total_memory() / 1024 / 1024;
        
        let threshold = std::env::var("SANDBOX_STRICT_RAM_MB")
            .unwrap_or_else(|_| "16384".to_string())
            .parse::<u64>()
            .unwrap_or(16384);

        info!("🛡️ [SysResourceManager] Booting. Total RAM: {} MB. Strict Sandbox Threshold: {} MB", total_ram_mb, threshold);

        Self {
            sys: Arc::new(Mutex::new(sys)),
            total_ram_mb,
            strict_threshold_mb: threshold,
        }
    }

    pub fn supports_strict_mode(&self) -> bool {
        self.total_ram_mb >= self.strict_threshold_mb
    }

    /// Calcula la RAM estimada para una herramienta basado en su categoría
    pub fn estimate_cost_mb(category: &str) -> u64 {
        match category.to_lowercase().as_str() {
            "scanner" | "cracker" | "exploitation" => 800,
            "webapp" | "fuzzer" => 300,
            _ => 50, // Herramientas de OSINT y light recon
        }
    }

    /// Actualiza la tabla de procesos y verifica si podemos destinar RAM.
    pub fn can_allocate(&self, req_mb: u64) -> bool {
        let mut sys = self.sys.lock().unwrap();
        sys.refresh_memory();
        let available_mb = sys.available_memory() / 1024 / 1024;
        
        if available_mb < req_mb {
             warn!("⚠️ [SysResourceManager] OOM Protection Activated! Requested: {} MB, but only {} MB available.", req_mb, available_mb);
             false
        } else {
             true
        }
    }
}
