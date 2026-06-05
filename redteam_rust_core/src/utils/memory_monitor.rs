use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fs;
use std::time::Duration;
use tracing::{info, warn, error};

pub struct MemoryMonitor {
    soft_limit_mb: u32,
    hard_limit_mb: u32,
    current: Arc<AtomicU64>,
    peak: Arc<AtomicU64>,
}

impl MemoryMonitor {
    pub fn new(soft_limit_mb: u32, hard_limit_mb: u32) -> Self {
        let monitor = Self {
            soft_limit_mb,
            hard_limit_mb,
            current: Arc::new(AtomicU64::new(0)),
            peak: Arc::new(AtomicU64::new(0)),
        };

        // Spawn background monitoring task
        let current_clone = Arc::clone(&monitor.current);
        let peak_clone = Arc::clone(&monitor.peak);
        
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1000)).await;
                
                #[cfg(target_os = "linux")]
                {
                    let current_clone = Arc::clone(&current_clone);
                    let peak_clone = Arc::clone(&peak_clone);
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Ok(status) = fs::read_to_string("/proc/self/status") {
                            for line in status.lines() {
                                if line.starts_with("VmRSS:") {
                                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                                        if let Ok(kb) = kb_str.parse::<u64>() {
                                            let bytes = kb * 1024;
                                            current_clone.store(bytes, Ordering::Relaxed);
                                            
                                            let p = peak_clone.load(Ordering::Relaxed);
                                            if bytes > p {
                                                peak_clone.store(bytes, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }).await;
                }
            }
        });

        monitor
    }

    pub fn current_mb(&self) -> u32 {
        (self.current.load(Ordering::Relaxed) / 1_000_000) as u32
    }

    pub fn soft_limit_mb(&self) -> u32 {
        self.soft_limit_mb
    }

    pub fn hard_limit_mb(&self) -> u32 {
        self.hard_limit_mb
    }

    pub fn peak_mb(&self) -> u32 {
        (self.peak.load(Ordering::Relaxed) / 1_000_000) as u32
    }

    pub fn should_trigger_backpressure(&self) -> bool {
        self.current_mb() > self.soft_limit_mb
    }

    pub fn is_critical(&self) -> bool {
        self.current_mb() > self.hard_limit_mb
    }

    pub fn start_logging(&self) {
        let curr_atom = Arc::clone(&self.current);
        let peak_atom = Arc::clone(&self.peak);
        let soft = self.soft_limit_mb;
        let hard = self.hard_limit_mb;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let curr = (curr_atom.load(Ordering::Relaxed) / 1_000_000) as u32;
                let peak = (peak_atom.load(Ordering::Relaxed) / 1_000_000) as u32;
                
                if curr > hard {
                    error!("CRITICAL: Memory {}MB/{}MB, triggering shutdown signal", curr, hard);
                    std::process::exit(1);
                } else if curr > soft {
                    warn!("Memory warning: {}MB/{}MB, activating backpressure", curr, soft);
                }
                
                info!("Memory Status: {}MB (Peak: {}MB)", curr, peak);
            }
        });
    }
}
