use reqwest::{Client, Proxy, header::HeaderValue};
use std::net::{IpAddr, SocketAddr};
use tokio_socks::tcp::Socks5Stream;
use std::sync::Arc;
use dashmap::DashMap;
use moka::sync::Cache;
use std::time::{SystemTime, Duration};
use tracing::{warn, error, info};
use anyhow::{Result, Context};
use std::collections::VecDeque;
use rand::seq::SliceRandom;
use std::sync::Mutex;
use crate::utils::config::ProxyMode;

const MAX_LATENCY_SAMPLES: usize = 10;
const _DEFAULT_BLACKLIST_DURATION: u64 = 300;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    pub fn url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("socks5h://{}:{}@{}:{}", u, p, self.host, self.port),
            (Some(u), None) => format!("socks5h://{}@{}:{}", u, self.host, self.port),
            _ => format!("socks5h://{}:{}", self.host, self.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedExit {
    pub last_seen: SystemTime,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub local_port: Option<u16>, // V14.1: Local port for Hysteria/SS clients
}

pub struct ProxyManager {
    proxies: Arc<Mutex<Vec<String>>>,
    clients: Cache<String, Client>,
    latency_stats: Cache<String, VecDeque<u64>>,
    insecure: bool,
    // Pool of modern browser User-Agents for rotation
    user_agents: Vec<String>,
    // RT-Identity: Map host -> User-Agent to maintain consistent identity
    identity_cache: Cache<String, String>,
    // Managed Exits (V13): IP addresses of DigitalOcean VPS nodes
    managed_exits: Arc<DashMap<String, ManagedExit>>,
    // V14.1 High-Speed Egress
    pub proxy_mode: ProxyMode,
    pub proxy_pool_size: u32,
    health_checker_handle: Option<tokio::task::AbortHandle>,
}

impl ProxyManager {
    pub fn new(proxies: Vec<String>, insecure: bool, proxy_mode: ProxyMode, proxy_pool_size: u32) -> Self {
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0".to_string(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0".to_string(),
        ];

        let mut pm = Self {
            proxies: Arc::new(Mutex::new(proxies)),
            clients: Cache::builder()
                .max_capacity((proxy_pool_size as u64 * 2).max(50))
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            latency_stats: Cache::builder()
                .max_capacity(1000)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            insecure,
            user_agents,
            identity_cache: Cache::builder()
                .max_capacity(2000)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
            managed_exits: Arc::new(DashMap::new()),
            proxy_mode,
            proxy_pool_size,
            health_checker_handle: None,
        };

        // Start background health checker if there can be proxies
        if !pm.lock_proxies().is_empty() {
             pm.start_health_checker();
        }

        pm
    }

    /// Robustness Fix (AUDIT-003): Handle poisoned mutexes without panicking
    fn lock_proxies(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        match self.proxies.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("Proxy Mutex is poisoned, recovering inner data.");
                poisoned.into_inner()
            }
        }
    }

    fn start_health_checker(&mut self) {
        if let Some(h) = self.health_checker_handle.take() {
            h.abort();
        }
        let managed_exits = self.managed_exits.clone();
        
        // QA-007 FIX: Store AbortHandle so the task is cancelled when ProxyManager is dropped
        let handle = tokio::spawn(async move {
            loop {
                let sleep_secs = {
                    let mut rng = rand::thread_rng();
                    rand::Rng::gen_range(&mut rng, 30..60) // V13: Faster auditing for supervisor
                };
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;


                
                /*
                // --- Part 1: Blacklist Recovery (Moka handles this automatically via TTL) ---
                */

                // --- Part 2: Managed Exit Auditing (V13 Supervisor) ---
                let mut to_prune = Vec::new();
                for entry in managed_exits.iter() {
                    let ip = entry.key().clone();
                    let exit = entry.value();
                    
                    // Prune by age (aggressive 12h for managed exits)
                    let elapsed = exit.last_seen.elapsed().unwrap_or(Duration::from_secs(0));
                    if elapsed.as_secs() > 43200 { 
                         to_prune.push(ip);
                         continue;
                    }

                    // V15.5 Hardware Check: TCP Ping
                    let addr_str = format!("{}:1080", ip);
                    match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(&addr_str)).await {
                        Ok(Ok(_)) => {
                            // Up
                        }
                        _ => {
                            warn!("🛡️ SUPERVISOR: Managed exit {} failed TCP health check. Pruning.", ip);
                            to_prune.push(ip);
                        }
                    }
                }

                for ip in to_prune {
                    managed_exits.remove(&ip);
                }
            }
        });
        self.health_checker_handle = Some(handle.abort_handle());
    }

    /// Internal method to lazily build a reqwest::Client for a specific proxy
    fn build_client(&self, proxy_str: Option<&str>, user_agent: String) -> Result<Client> {
        let mut builder = reqwest::Client::builder()
            .user_agent(user_agent)
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"));
                h.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));
                h.insert("Sec-Ch-Ua", HeaderValue::from_static("\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"122\", \"Chromium\";v=\"122\""));
                h.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
                h.insert("Sec-Ch-Ua-Platform", HeaderValue::from_static("\"Windows\""));
                h.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
                h.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
                h.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
                h.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
                h.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
                h
            })
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15));

        if let Some(p_str) = proxy_str {
            let proxy = Proxy::all(p_str).context("Invalid proxy URL")?;
            builder = builder.proxy(proxy);
        }
            
        builder.build().context("Failed to build reqwest client")
    }

    /// Build a host-pinned client for a specific proxy
    fn build_client_pinned(&self, proxy_str: &str, host: &str, ip: IpAddr, port: u16, user_agent: String) -> Result<Client> {
        let proxy = Proxy::all(proxy_str).context("Invalid proxy URL")?;
        
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .user_agent(user_agent)
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert("Accept", HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"));
                h.insert("Accept-Language", HeaderValue::from_static("en-US,en;q=0.9"));
                h.insert("Sec-Ch-Ua", HeaderValue::from_static("\"Not A(Brand\";v=\"99\", \"Google Chrome\";v=\"122\", \"Chromium\";v=\"122\""));
                h.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
                h.insert("Sec-Ch-Ua-Platform", HeaderValue::from_static("\"Windows\""));
                h.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
                h.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
                h.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
                h.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
                h.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
                h
            })
            .resolve(host, SocketAddr::new(ip, port))
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(15))
            .build()
            .context("Failed to build host-pinned reqwest client for proxy")?;
            
        Ok(client)
    }

    fn pick_user_agent(&self) -> String {
        let mut rng = rand::thread_rng();
        self.user_agents.choose(&mut rng).cloned().unwrap_or_else(|| "Mozilla/5.0".to_string())
    }

    /// Report latency for a proxy to improve selection intelligence
    pub fn report_latency(&self, proxy: &str, duration_ms: u64) {
        let mut stats = self.latency_stats.get(proxy).unwrap_or_default();
        stats.push_back(duration_ms);
        if stats.len() > MAX_LATENCY_SAMPLES {
            stats.pop_front();
        }
        self.latency_stats.insert(proxy.to_string(), stats);
    }

    fn get_average_latency(&self, proxy: &str) -> u64 {
        if let Some(stats) = self.latency_stats.get(proxy) {
            if stats.is_empty() { return 1000; } // Default high-ish starting point
            let sum: u64 = stats.iter().sum();
            sum / stats.len() as u64
        } else {
            1000 // Unknown proxies start here
        }
    }

    /// Selection intelligence: finds the best available proxy based on latency
    /// but keeps a small chance of picking a random one to discover improvements.
    /// V13: Now includes Managed Exits (DigitalOcean VPS) in the pool.
    fn pick_best_proxy(&self) -> Option<String> {
        let mut candidates: Vec<String> = {
            let proxies_lock = self.lock_proxies();
            proxies_lock.iter()
                .cloned()
                .collect()
        };

        // Inject managed exits into candidates
        for entry in self.managed_exits.iter() {
            let ip = entry.key();
            let exit = entry.value();
            
            let proxy_url = if let Some(local_port) = exit.local_port {
                // High-Speed Mode: Point to local SOCKS5 hub
                format!("socks5h://127.0.0.1:{}", local_port)
            } else if let (Some(u), Some(p)) = (&exit.user, &exit.pass) {
                format!("socks5h://{}:{}@{}:1080", u, p, ip)
            } else {
                format!("socks5h://{}:1080", ip)
            };
            // Managed exits are generally high priority, don't blacklist them here 
            // unless we implement a separate VPS health check
            candidates.push(proxy_url);
        }

        if candidates.is_empty() { return None; }

        // 10% chance to pick purely random for discovery
        let mut rng = rand::thread_rng();
        if rand::Rng::gen_bool(&mut rng, 0.1) {
             return candidates.choose(&mut rng).cloned();
        }

        // Otherwise, pick the one with lowest average latency
        candidates.into_iter()
            .min_by_key(|p| self.get_average_latency(p))
    }

    /// V13: Get a random available managed exit node formatted as a SOCKS5/4 URL.
    pub fn get_best_socks_url(&self) -> Option<String> {
        let managed: Vec<String> = self.managed_exits.iter()
            .map(|e| e.key().clone())
            .collect();
            
        if !managed.is_empty() {
             let mut rng = rand::thread_rng();
             let ip = managed.choose(&mut rng)?;
             
             if let Some(exit) = self.managed_exits.get(ip) {
                 if let Some(local_port) = exit.local_port {
                     return Some(format!("socks5h://127.0.0.1:{}", local_port));
                 }
                 if let (Some(u), Some(p)) = (&exit.user, &exit.pass) {
                     return Some(format!("socks5h://{}:{}@{}:1080", u, p, ip));
                 }
             }
             
             // DigitalOcean managed nodes run danted on 1080
             return Some(format!("socks5h://{}:1080", ip));
        }
        
        // Fallback to static proxies if they are SOCKS
        let best = self.pick_best_proxy()?;
        if best.starts_with("socks") {
            Some(best)
        } else {
            None
        }
    }

    /// V13: Wraps a std::process::Command with tool-specific proxy flags or proxychains.
    pub fn wrap_command(&self, tool: &str, args: &mut Vec<String>) -> Result<()> {
        if let Some(proxy_url) = self.get_best_socks_url() {
            match tool.to_lowercase().as_str() {
                "curl" => {
                    args.insert(0, "-x".to_string());
                    args.insert(1, proxy_url);
                }
                "nmap" => {
                    let nmap_proxy = proxy_url.replace("socks5h://", "socks4://");
                    args.push("--proxies".to_string());
                    args.push(nmap_proxy);
                }
                _ => {
                    // Professional Mode: Use proxychains-ng for everything else
                    info!("🛡️ ProxyManager: Wrapping '{}' with proxychains-ng via {}", tool, proxy_url);
                    let clean_proxy = proxy_url.strip_prefix("socks5h://").unwrap_or(&proxy_url).strip_prefix("socks5://").unwrap_or(&proxy_url);
                    let addr_part = clean_proxy.split('@').next_back().unwrap_or(clean_proxy);
                    let parts: Vec<&str> = addr_part.split(':').collect();
                    
                    if parts.len() == 2 {
                        let ip = parts[0];
                        let port = parts[1];
                        let conf = format!("strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5 {} {}\n", ip, port);
                        
                        let conf_path = std::env::temp_dir().join(format!("px_{}_{}.conf", std::process::id(), rand::random::<u32>()));
                        if let Err(e) = std::fs::write(&conf_path, conf) {
                            warn!("Failed to write proxychains config: {}", e);
                            args.insert(0, tool.to_string());
                        } else {
                            args.insert(0, tool.to_string());
                            args.insert(0, conf_path.to_string_lossy().into_owned());
                            args.insert(0, "-f".to_string());
                        }
                    } else {
                        args.insert(0, tool.to_string());
                    }
                }
            }
            Ok(())
        } else {
            anyhow::bail!("V13 OPSEC Violation: No proxy available for command wrapping.")
        }
    }

    /// V14.1 Professional: Applies the best available proxy to a ClientBuilder.
    pub fn configure_client_builder(&self, mut builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        let proxy_url = self.pick_best_proxy()
            .context("V14.1 OPSEC Violation: No proxy available for client configuration.")?;
        
        let proxy = Proxy::all(proxy_url).context("Invalid proxy URL")?;
        builder = builder.proxy(proxy);
        
        Ok(builder)
    }

    pub fn add_managed_exit_with_auth(&self, ip: String, user: &str, pass: &str) {
        let max_nodes = (self.proxy_pool_size as usize * 2).max(10);
        if self.managed_exits.len() >= max_nodes {
            warn!("⚠️ Managed exit pool full ({} nodes). Rejecting {}", self.managed_exits.len(), ip);
            return;
        }
        let mut local_port = None;
        if self.proxy_mode == ProxyMode::Hysteria {
            let port = 10000 + (rand::random::<u16>() % 10000); // Random high port for local SOCKS
            if self.spawn_local_proxy_client(&ip, port, pass).is_ok() {
                local_port = Some(port);
            }
        }

        self.managed_exits.insert(ip.clone(), ManagedExit {
            last_seen: SystemTime::now(),
            user: Some(user.to_string()),
            pass: Some(pass.to_string()),
            local_port,
        });
        info!("🚀 ProxyManager: Active DO Managed Exit added with professional authentication: {} (Local Port: {:?})", ip, local_port);
    }

    fn spawn_local_proxy_client(&self, remote_ip: &str, local_port: u16, auth: &str) -> Result<()> {
        use tokio::process::Command;
        use crate::utils::downloader::ensure_hysteria_binary;
        
        let remote_ip = remote_ip.to_string();
        let auth = auth.to_string();

        tokio::spawn(async move {
            let bin = match ensure_hysteria_binary().await {
                Ok(b) => b,
                Err(e) => {
                    error!("❌ STEALTH: Failed to ensure Hysteria binary: {}", e);
                    return;
                }
            };

            info!("🛡️ STEALTH: Spawning local Hysteria client for {} on port {}...", remote_ip, local_port);
            
            let config_content = format!(r#"
server: {}:1080
auth: {}
socks5:
  listen: 127.0.0.1:{}
transport:
  udp:
    hop: true
"#, remote_ip, auth, local_port);

            let config_path = std::env::temp_dir().join(format!("hysteria_{}.yaml", local_port));
            if let Err(e) = tokio::fs::write(&config_path, config_content).await {
                error!("❌ STEALTH: Failed to write Hysteria client config: {}", e);
                return;
            }

            match Command::new(bin)
                .arg("client")
                .arg("-c")
                .arg(&config_path)
                .kill_on_drop(true)
                .spawn() {
                    Ok(mut child) => {
                        info!("🚀 STEALTH: Hysteria local client PID {:?} established for {}", child.id(), remote_ip);
                        let _ = child.wait().await;
                    }
                    Err(e) => error!("❌ STEALTH: Failed to spawn Hysteria client: {}", e),
                }
        });

        Ok(())
    }

    pub fn add_managed_exit(&self, ip: String) {
        let max_nodes = (self.proxy_pool_size as usize * 2).max(10);
        if self.managed_exits.len() >= max_nodes {
            warn!("⚠️ Managed exit pool full ({} nodes). Rejecting {}", self.managed_exits.len(), ip);
            return;
        }
        self.managed_exits.insert(ip.clone(), ManagedExit {
            last_seen: SystemTime::now(),
            user: None,
            pass: None,
            local_port: None,
        });
        info!("🚀 ProxyManager: Active DO Managed Exit added (Anonymous): {}", ip);
    }
    
    pub fn get_managed_exits(&self) -> Vec<String> {
        self.managed_exits.iter().map(|e| e.key().clone()).collect()
    }

    pub fn get_client(&self, host: &str) -> Option<(String, Client)> {
        if self.is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
        // RT-Identity: Ensure same User-Agent for this host
        let ua = self.identity_cache.get(host)
            .unwrap_or_else(|| {
                let picked = self.pick_user_agent();
                self.identity_cache.insert(host.to_string(), picked.clone());
                picked
            });

        let cache_key = format!("{}:{}", p_url, ua);
        
        if let Some(client) = self.clients.get(&cache_key) {
            return Some((p_url, client));
        }

        match self.build_client(Some(&p_url), ua) {
            Ok(client) => {
                self.clients.insert(cache_key, client.clone());
                Some((p_url, client))
            }
            Err(e) => {
                error!("Failed to initialize proxy {}: {}", p_url, e);
                None
            }
        }
    }

    /// V14.1 Professional: Returns a client guaranteed to bypass proxies for loopback/internal traffic.
    pub fn get_localhost_client(&self, host: &str) -> Result<(String, Client)> {
        let ua = self.identity_cache.get(host)
            .unwrap_or_else(|| {
                let picked = self.pick_user_agent();
                self.identity_cache.insert(host.to_string(), picked.clone());
                picked
            });

        let client = self.build_client(None, ua.clone())?;
        Ok(("localhost".to_string(), client))
    }

    /// V13: Fail-Closed client acquisition. Refuses to return a local client if stealth is active and proxies are down.
    pub fn get_client_fail_closed(&self, host: &str) -> Result<(String, Client)> {
        self.get_client(host)
            .context(format!("V13 OPSEC Violation: No proxy available for host {}. Aborting to prevent leak.", host))
    }

    /// V13: Establishes a raw TCP connection through a random available SOCKS5 manager node.
    pub async fn tcp_connect_proxied(&self, target_host: &str, target_port: u16) -> Result<tokio::net::TcpStream> {
        let proxy_url = self.get_best_socks_url()
            .context("V13 OPSEC Violation: No SOCKS5 proxy available for TCP connection.")?;
        
        let proxy_addr = proxy_url.strip_prefix("socks5h://")
            .or_else(|| proxy_url.strip_prefix("socks5://"))
            .unwrap_or(&proxy_url);
        
        let proxy_sock_addr: SocketAddr = if proxy_addr.contains(':') {
            proxy_addr.parse()?
        } else {
            format!("{}:1080", proxy_addr).parse()?
        };

        info!("🛡️ V13: Routing TCP connection to {}:{} via {}", target_host, target_port, proxy_addr);
        
        let stream = Socks5Stream::connect(proxy_sock_addr, (target_host, target_port)).await
            .map_err(|e| anyhow::anyhow!("SOCKS5 Handshake failed: {}", e))?;
        
        Ok(stream.into_inner())
    }

    pub fn get_client_pinned(&self, host: &str, ip: IpAddr, port: u16) -> Option<(String, Client)> {
        if self.is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
        let ua = self.identity_cache.get(host)
            .unwrap_or_else(|| {
                let picked = self.pick_user_agent();
                self.identity_cache.insert(host.to_string(), picked.clone());
                picked
            });

        let cache_key = format!("{}:{}:{}:{}:{}", p_url, host, ip, port, ua);
        
        if let Some(client) = self.clients.get(&cache_key) {
            return Some((p_url, client));
        }

        match self.build_client_pinned(&p_url, host, ip, port, ua) {
            Ok(client) => {
                self.clients.insert(cache_key, client.clone());
                Some((p_url, client))
            }
            Err(e) => {
                error!("Failed to initialize pinned proxy {}: {}", p_url, e);
                None
            }
        }
    }

    pub fn get_human_delay(&self) -> Duration {
        use rand_distr::{Distribution, LogNormal};
        let mut rng = rand::thread_rng();
        let normal = LogNormal::new(1.0, 0.5).unwrap();
        let sample = normal.sample(&mut rng);
        Duration::from_millis((sample * 1000.0) as u64)
    }

    pub fn get_adaptive_delay(&self, proxy: &str) -> Duration {
        let base_delay = self.get_human_delay();
        let multiplier = if let Some(stats) = self.latency_stats.get(proxy) {
            let avg = if stats.is_empty() { 1000 } else { stats.iter().sum::<u64>() / stats.len() as u64 };
            if avg > 2000 { 1.5 } else { 1.0 }
        } else {
            1.0
        };
        base_delay.mul_f64(multiplier)
    }

    pub fn add_proxy(&self, proxy: String) {
        let mut proxies = self.lock_proxies();
        if !proxies.contains(&proxy) {
            proxies.push(proxy);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lock_proxies().is_empty() && self.managed_exits.is_empty()
    }

    pub async fn wait_for_readiness(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        let check_url = std::env::var("INTERACTSH_SERVER_URL")
            .unwrap_or_else(|_| "http://1.1.1.1".to_string());
        
        info!("⏳ STEALTH: Waiting for Egress Readiness Gate (Checking vs {})...", check_url);
        
        while start.elapsed() < timeout {
            if !self.is_empty() {
                // Pick a proxy and try a real HEAD request
                if let Some((_url, client)) = self.get_client("readiness-check.com") {
                    match tokio::time::timeout(Duration::from_secs(5), client.head(&check_url).send()).await {
                        Ok(Ok(resp)) if resp.status().is_success() || resp.status().is_redirection() => {
                            info!("🛡️ STEALTH: Egress readiness verified via functional proxy. {} nodes available.", 
                                self.lock_proxies().len() + self.managed_exits.len());
                            return Ok(());
                        }
                        Ok(Ok(resp)) => {
                            warn!("⚠️ STEALTH: Proxy responded but check failed (Status: {}). Retrying...", resp.status());
                        }
                        _ => {
                            warn!("⚠️ STEALTH: Selected proxy failed connectivity check. Blacklisting and retrying...");
                            // connectivity failure handled elsewhere
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        
        anyhow::bail!("V15.5 OPSEC Critical: Timeout exceeded waiting for functional egress. Aborting mission.")
    }
}

impl Drop for ProxyManager {
    fn drop(&mut self) {
        if let Some(handle) = self.health_checker_handle.take() {
            handle.abort();
        }
        info!("ProxyManager: Shutting down.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_proxy_config_url() {
        let cfg = ProxyConfig {
            host: "1.2.3.4".to_string(),
            port: 1080,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
        };
        assert_eq!(cfg.url(), "socks5h://user:pass@1.2.3.4:1080");
    }
}
