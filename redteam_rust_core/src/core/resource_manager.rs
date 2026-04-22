use sysinfo::System;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Clone)]
pub struct SysResourceManager {
    _sys: Arc<Mutex<System>>,
    pub total_ram_mb: u64,
    pub strict_threshold_mb: u64, 
    available_ram_mb: Arc<std::sync::atomic::AtomicU64>,
}

impl Default for SysResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SysResourceManager {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_memory();
        // sysinfo 0.30+ uses bytes exclusively
        let total_ram_mb = sys.total_memory() / 1024 / 1024;
        let available_ram_mb = Arc::new(std::sync::atomic::AtomicU64::new(sys.available_memory() / 1024 / 1024));
        
        let threshold = std::env::var("SANDBOX_STRICT_RAM_MB")
            .unwrap_or_else(|_| "16384".to_string())
            .parse::<u64>()
            .unwrap_or(16384);

        info!("🛡️ [SysResourceManager] Booting. Total RAM: {} MB. Strict Sandbox Threshold: {} MB", total_ram_mb, threshold);

        let sys_arc = Arc::new(Mutex::new(sys));
        let sys_clone = sys_arc.clone();
        let avail_clone = available_ram_mb.clone();

        // PERF-02: Background refresh task to avoid Mutex contention in hot-path
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
            loop {
                interval.tick().await;
                let mut sys = sys_clone.lock().unwrap();
                sys.refresh_memory();
                avail_clone.store(sys.available_memory() / 1024 / 1024, std::sync::atomic::Ordering::Relaxed);
            }
        });

        Self {
            _sys: sys_arc,
            total_ram_mb,
            strict_threshold_mb: threshold,
            available_ram_mb,
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
        // PERF-02: Use atomic read instead of Mutex lock + refresh_memory in hot-path
        let available_mb = self.available_ram_mb.load(std::sync::atomic::Ordering::Relaxed);
        
        if available_mb < req_mb {
             warn!("⚠️ [SysResourceManager] OOM Protection Activated! Requested: {} MB, but only {} MB available.", req_mb, available_mb);
             false
        } else {
             true
        }
    }
}
