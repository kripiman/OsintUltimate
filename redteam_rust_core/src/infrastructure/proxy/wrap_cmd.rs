use tracing::info;
use anyhow::Result;
use super::manager::ProxyManager;

impl ProxyManager {
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
                            tracing::warn!("Failed to write proxychains config: {}", e);
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
}
