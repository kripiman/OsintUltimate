

pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    pub fn url(&self) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("socks5://{}:{}@{}:{}", u, p, self.host, self.port),
            (Some(u), None) => format!("socks5://{}@{}:{}", u, self.host, self.port),
            _ => format!("socks5://{}:{}", self.host, self.port),
        }
    }
}

pub struct ProxyManager;

impl ProxyManager {
    pub fn from_droplet_ip(ip: &str) -> ProxyConfig {
        ProxyConfig {
            host: ip.to_string(),
            port: 1080,
            username: None,
            password: None,
        }
    }
}

