use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use tracing::info;
use anyhow::{Result, Context};
use std::sync::Arc;
use crate::utils::proxy::ProxyManager;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Serialize, Deserialize)]
pub struct Droplet {
    pub id: u64,
    pub name: String,
    pub networks: Networks,
    pub status: String,
    #[serde(skip)]
    pub socks_user: Option<String>,
    #[serde(skip)]
    pub socks_pass: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Networks {
    pub v4: Vec<Network>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Network {
    pub ip_address: String,
    pub r#type: String,
}

impl Droplet {
    pub fn public_ip(&self) -> Option<String> {
        self.networks.v4.iter()
            .find(|n| n.r#type == "public")
            .map(|n| n.ip_address.clone())
    }
}

#[derive(Debug, Serialize)]
struct CreateDropletRequest {
    name: String,
    region: String,
    size: String,
    image: String,
    ssh_keys: Vec<String>,
    backups: bool,
    ipv6: bool,
    monitoring: bool,
    tags: Vec<String>,
    user_data: Option<String>,
}

use crate::utils::config::ProxyMode;

fn generate_proxy_user_data(mode: ProxyMode, user: &str, pass: &str) -> String {
    match mode {
        ProxyMode::Dante => format!(r#"#cloud-config
package_update: true
packages:
  - dante-server
write_files:
  - path: /etc/danted.conf
    content: |
      logoutput: stderr
      internal: 0.0.0.0 port = 1080
      external: eth0
      socksmethod: username
      user.privileged: root
      user.unprivileged: nobody
      
      client method: username
      client pass {{
          from: 0.0.0.0/0
          to: 0.0.0.0/0
          socksmethod: username
      }}
      
      socks pass {{
          from: 0.0.0.0/0
          to: 0.0.0.0/0
          protocol: tcp udp
          socksmethod: username
      }}
runcmd:
  - useradd -M -s /usr/sbin/nologin {user}
  - echo "{user}:{pass}" | chpasswd
  - systemctl restart danted
  - shutdown -h +120
"#, user = user, pass = pass),
        ProxyMode::Shadowsocks => format!(r#"#cloud-config
package_update: true
packages:
  - docker.io
runcmd:
  - docker run -d --name ss-server --restart always -p 1080:8388 shadowsocks/shadowsocks-libev ss-server -s 0.0.0.0 -p 8388 -k {pass} -m aes-256-gcm
  - shutdown -h +120
"#, pass = pass),
        ProxyMode::Hysteria => format!(r#"#cloud-config
package_update: true
runcmd:
  - wget https://github.com/apernet/hysteria/releases/download/app%2Fv2.5.2/hysteria-linux-amd64 -O /usr/local/bin/hysteria
  - echo "13fcedd6aa1aabac6c905fbd598cfc84dd2e35384bc133464ffdd1c97a4cfdb6  /usr/local/bin/hysteria" | sha256sum -c || shutdown -h now
  - chmod +x /usr/local/bin/hysteria
  - openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/hysteria.key -out /etc/hysteria.crt -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
  - echo "listen: :1080" > /etc/hysteria.yaml
  - echo "cert: /etc/hysteria.crt" >> /etc/hysteria.yaml
  - echo "key: /etc/hysteria.key" >> /etc/hysteria.yaml
  - echo "auth: {pass}" >> /etc/hysteria.yaml
  - hysteria server -c /etc/hysteria.yaml &
  - shutdown -h +120
"#, pass = pass),
        ProxyMode::None => String::new(),
    }
}

pub struct DigitalOceanClient {
    proxy_manager: Arc<ProxyManager>,
    token: String,
}

impl DigitalOceanClient {
    pub fn new(token: String, pm: Arc<ProxyManager>) -> Self {
        Self {
            proxy_manager: pm,
            token,
        }
    }

    fn get_client(&self) -> Result<reqwest::Client> {
        let (_, client) = self.proxy_manager.get_client_fail_closed("api.digitalocean.com")?;
        Ok(client)
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let auth_val = HeaderValue::from_str(&format!("Bearer {}", self.token))
            .context("Invalid DigitalOcean token format for AUTHORIZATION header")?;
        
        headers.insert(AUTHORIZATION, auth_val);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(headers)
    }

    pub async fn create_droplet(&self, name: &str, region: &str, mode: ProxyMode) -> Result<Droplet> {
        let socks_user = "operator"; 
        let socks_pass = uuid::Uuid::new_v4().to_string()[..12].to_string(); // Professional entropy

        let mut ssh_keys = vec![];
        if let Ok(key) = std::env::var("DO_SSH_KEY_ID") {
            ssh_keys.push(key);
        }

        let request = CreateDropletRequest {
            name: name.to_string(),
            region: region.to_string(),
            size: "s-1vcpu-512mb".to_string(),
            image: "ubuntu-22-04-x64".to_string(),
            ssh_keys, 
            backups: false,
            ipv6: false,
            monitoring: true,
            tags: vec!["osint-ultimate".to_string(), "ephemeral".to_string()],
            user_data: Some(generate_proxy_user_data(mode, socks_user, &socks_pass)),
        };

        let response = self.get_client()?
            .post("https://api.digitalocean.com/v2/droplets")
            .headers(self.headers()?)
            .json(&request)
            .send()
            .await?
            .error_for_status()?;

        #[derive(Deserialize)]
        struct DropletWrapper {
            droplet: Droplet,
        }

        let mut wrapper: DropletWrapper = response.json().await?;
        wrapper.droplet.socks_user = Some(socks_user.to_string());
        wrapper.droplet.socks_pass = Some(socks_pass);
        
        Ok(wrapper.droplet)
    }

    pub async fn get_droplet(&self, id: u64) -> Result<Droplet> {
        let response = self.get_client()?
            .get(format!("https://api.digitalocean.com/v2/droplets/{}", id))
            .headers(self.headers()?)
            .send()
            .await?
            .error_for_status()?;

        #[derive(Deserialize)]
        struct DropletWrapper {
            droplet: Droplet,
        }

        let wrapper: DropletWrapper = response.json().await?;
        Ok(wrapper.droplet)
    }

    pub async fn wait_for_ip(&self, id: u64) -> Result<String> {
        for _ in 0..60 { // Wait up to 10 minutes (DO is fast but let's be safe)
            let droplet = self.get_droplet(id).await?;
            
            if let Some(ip) = droplet.public_ip() {
                return Ok(ip);
            }
            
            sleep(Duration::from_secs(10)).await;
        }
        anyhow::bail!("Timeout waiting for Droplet IP")
    }

    pub async fn destroy_droplet(&self, id: u64) -> Result<()> {
        self.get_client()?
            .delete(format!("https://api.digitalocean.com/v2/droplets/{}", id))
            .headers(self.headers()?)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn list_droplets(&self) -> Result<Vec<Droplet>> {
        let response = self.get_client()?
            .get("https://api.digitalocean.com/v2/droplets?tag_name=osint-ultimate")
            .headers(self.headers()?)
            .send()
            .await?
            .error_for_status()?;

        #[derive(Deserialize)]
        struct DropletsWrapper {
            droplets: Vec<Droplet>,
        }

        let wrapper: DropletsWrapper = response.json().await?;
        Ok(wrapper.droplets)
    }

    pub async fn destroy_all_ephemeral_droplets(&self) -> Result<()> {
        let droplets = self.list_droplets().await?;
        for d in droplets {
            info!("🛡️ KILL-SWITCH: Destroying ephemeral droplet {} (ID: {})...", d.name, d.id);
            let _ = self.destroy_droplet(d.id).await;
        }
        Ok(())
    }
}
