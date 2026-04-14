use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
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

const PROXY_USER_DATA: &str = r#"#cloud-config
package_update: true
packages:
  - dante-server
write_files:
  - path: /etc/danted.conf
    content: |
      logoutput: stderr
      internal: 0.0.0.0 port = 1080
      external: eth0
      socksmethod: none
      clientmethod: none
      client pass {
          from: 0.0.0.0/0
          to: 0.0.0.0/0
      }
      socks pass {
          from: 0.0.0.0/0
          to: 0.0.0.0/0
          protocol: tcp udp
      }
runcmd:
  - systemctl restart danted
  - shutdown -h +240
"#;

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

    pub async fn create_droplet(&self, name: &str, region: &str) -> Result<Droplet> {
        let request = CreateDropletRequest {
            name: name.to_string(),
            region: region.to_string(),
            size: "s-1vcpu-1gb".to_string(), // Cheapest option: $6/mo
            image: "ubuntu-22-04-x64".to_string(),
            ssh_keys: vec![], // TODO: Add SSH key support
            backups: false,
            ipv6: false,
            monitoring: true,
            tags: vec!["osint-ultimate".to_string(), "ephemeral".to_string()],
            user_data: Some(PROXY_USER_DATA.to_string()),
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

        let wrapper: DropletWrapper = response.json().await?;
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
}
