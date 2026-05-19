use rand_distr::{LogNormal, Distribution};
use tokio::time::{sleep, Duration};
use tracing::error;
 // V9 FIX (MEDIUM-002): std::sync::RwLock for brief RAM-only blacklist access

pub struct HumanJitter {
    min_delay_ms: f64, // Changed to float for LogNormal calc
    max_delay_ms: f64,
    dist: LogNormal<f64>,
}

impl HumanJitter {
    pub fn new(min_delay_ms: u64, max_delay_ms: u64) -> Self {
        // LogNormal params: mean=0.5, std_dev=0.8 (simulating human reaction)
        let dist = LogNormal::new(0.5, 0.8).unwrap();
        Self {
            min_delay_ms: min_delay_ms as f64,
            max_delay_ms: max_delay_ms as f64,
            dist,
        }
    }

    pub async fn sleep(&self) {
        let base_delay = self.dist.sample(&mut rand::thread_rng()) * 1000.0; // Scale factor
        let delay = base_delay.clamp(self.min_delay_ms, self.max_delay_ms);
        sleep(Duration::from_millis(delay as u64)).await;
    }
}

// ProxyManager moved to utils::proxy
// Stealth: Realistic Browser User-Agents
const REALISTIC_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
];

pub fn get_random_user_agent() -> &'static str {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    REALISTIC_USER_AGENTS.choose(&mut rng).unwrap_or(&REALISTIC_USER_AGENTS[0])
}

/// QA-008 FIX: Check actual CAP_NET_RAW capability, not just euid == 0
pub fn check_cap_net_raw() -> bool {
    #[cfg(unix)]
    {
        // Try reading actual effective capabilities from /proc/self/status
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex_str) = line.strip_prefix("CapEff:") {
                    let hex_str = hex_str.trim();
                    if let Ok(caps) = u64::from_str_radix(hex_str, 16) {
                        return caps & (1 << 13) != 0; // CAP_NET_RAW = bit 13
                    }
                }
            }
        }
        // Fallback: euid check if procfs is unavailable (e.g., containers with restricted /proc)
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        // On non-Unix, assume true and let nmap handle permission errors
        true
    }
}

/// STEALTH-003: Tactical Command Wrapper
/// 1. env_clear(): Strips RUST_*, CARGO_*, and other parent env vars.
/// 2. setsid/process_group: Decouples from the parent's process tree signaling.
/// 3. Resource Limits: Enforces virtual memory constraints to protect the 1GB RAM host.
/// 4. V12 Enterprise: Global Proxy Enforcement (ALL_PROXY)
pub fn stealth_command(binary: &str, pm: Option<&crate::utils::proxy::ProxyManager>) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(binary);
    
    cmd.env_clear()
       .env("PATH", "/usr/local/bin:/usr/bin:/bin")
       .env("HOME", "/tmp")
       .kill_on_drop(true);

    // V12 HARDENING: Global Proxy Enforcement
    // V14.1 Professional: Prefer live ProxyManager over static environment variable.
    if let Some(pm) = pm {
        if let Some(proxy_url) = pm.get_best_socks_url() {
            cmd.env("ALL_PROXY", proxy_url.clone())
               .env("http_proxy", proxy_url.clone())
               .env("https_proxy", proxy_url);
        }
    } else if let Ok(proxy) = std::env::var("GLOBAL_SCAN_PROXY") {
        cmd.env("ALL_PROXY", proxy.clone())
           .env("http_proxy", proxy.clone())
           .env("https_proxy", proxy);
    }

    #[cfg(unix)]
    {
        // Setsid / process group 0 to prevent Ctrl-C or parent signals from killing children
        // independently of our orchestrator's explicit management.
        unsafe {
            cmd.pre_exec(|| {
                // 1. New Session/PGID
                libc::setsid();
                
                // 2. Memory Limits (Hard limit 512MB for any single tool)
                // This prevents a single nmap/hydra from OOMing the 1GB VPS.
                let mem_limit_val = 512 * 1024 * 1024; // 512 MB
                let mem_rlimit = libc::rlimit {
                    rlim_cur: mem_limit_val,
                    rlim_max: mem_limit_val,
                };
                libc::setrlimit(libc::RLIMIT_AS, &mem_rlimit);
                
                // 3. CPU Time Limit (300s CPU time max to prevent runaway processes)
                let cpu_rlimit = libc::rlimit {
                    rlim_cur: 300,
                    rlim_max: 300,
                };
                libc::setrlimit(libc::RLIMIT_CPU, &cpu_rlimit);

                // 4. Process Count Limit (Max 64 children to prevent fork bombs/runaway threads)
                let nproc_rlimit = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                libc::setrlimit(libc::RLIMIT_NPROC, &nproc_rlimit);
                
                Ok(())
            });
        }
    }

    cmd
}

pub async fn kill_pgid(pid: u32) {
    #[cfg(unix)]
    {
        // V11 HARDENING (HIGH-003): Guard against killing pid 0, 1 or negative (which would kill all processes)
        if pid <= 1 {
            error!("Refusing to kill PGID {} as it is a restricted system PID.", pid);
            return;
        }
        // Sending signal to -pid sends it to the whole process group.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

pub fn kill_pgid_sync(pid: u32) {
    #[cfg(unix)]
    {
        if pid <= 1 { return; }
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

pub struct PgidKillGuard {
    pub pgid: u32,
}

impl PgidKillGuard {
    pub fn new(pgid: u32) -> Self { Self { pgid } }
}

impl Drop for PgidKillGuard {
    fn drop(&mut self) {
        kill_pgid_sync(self.pgid);
    }
}

pub fn extract_json(text: &str) -> &str {
    let start_curly = text.find('{');
    let start_bracket = text.find('[');

    match (start_curly, start_bracket) {
        (Some(c), Some(b)) => {
            if c < b {
                if let Some(end) = text.rfind('}') {
                    return &text[c..=end];
                }
            } else {
                if let Some(end) = text.rfind(']') {
                    return &text[b..=end];
                }
            }
        }
        (Some(c), None) => {
            if let Some(end) = text.rfind('}') {
                return &text[c..=end];
            }
        }
        (None, Some(b)) => {
            if let Some(end) = text.rfind(']') {
                return &text[b..=end];
            }
        }
        (None, None) => {}
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jitter_range() {
        let jitter = HumanJitter::new(10, 20);
        // We can't easily test duration without mocking time or statistical analysis.
        // But we can ensure it doesn't panic.
        jitter.sleep().await;
        // Pass
    }
}
