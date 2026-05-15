use reqwest::{Client, Proxy, header::HeaderValue};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use anyhow::{Result, Context};
use tracing::{info, error};
use crate::utils::config::ProxyMode;
use super::manager::ProxyManager;
use tokio_socks::tcp::Socks5Stream;

impl ProxyManager {
    /// Internal method to lazily build a reqwest::Client for a specific proxy
    pub(crate) fn build_client(&self, proxy_str: Option<&str>, user_agent: String) -> Result<Client> {
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
    pub(crate) fn build_client_pinned(&self, proxy_str: &str, host: &str, ip: IpAddr, port: u16, user_agent: String) -> Result<Client> {
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

    pub fn configure_client_builder(&self, mut builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        if self.proxy_mode == ProxyMode::None {
            return Ok(builder);
        }

        let proxy_url = self.pick_best_proxy()
            .context("V14.1 OPSEC Violation: No proxy available for client configuration.")?;
        
        let proxy = Proxy::all(proxy_url).context("Invalid proxy URL")?;
        builder = builder.proxy(proxy);
        
        Ok(builder)
    }

    pub fn configure_stealth_builder(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        self.configure_client_builder(builder)
    }

    pub fn get_client(&self, host: &str) -> Option<(String, Client)> {
        if self.proxy_mode == ProxyMode::None {
             let ua = self.identity_cache.get(host)
                .unwrap_or_else(|| {
                    let picked = self.pick_user_agent();
                    self.identity_cache.insert(host.to_string(), picked.clone());
                    picked
                });
             return self.build_client(None, ua).ok().map(|c| ("direct".to_string(), c));
        }

        if self.is_empty() { return None; }

        let p_url = self.pick_best_proxy()?;
        
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

    pub fn get_stealth_client(&self, host: &str) -> Option<(String, reqwest::Client)> {
        self.get_client(host)
    }

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

    pub fn get_client_fail_closed(&self, host: &str) -> Result<(String, Client)> {
        self.get_client(host)
            .context(format!("V13 OPSEC Violation: No proxy available for host {}. Aborting to prevent leak.", host))
    }

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

    pub fn get_stealth_client_pinned(&self, host: &str, ip: IpAddr, port: u16) -> Option<(String, reqwest::Client)> {
        self.get_client_pinned(host, ip, port)
    }
}
