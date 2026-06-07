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

fn generate_user_data(mode: ProxyMode, user: &str, pass: &str) -> String {
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
        ProxyMode::Worker => {
            let binary_url = std::env::var("DO_WORKER_BINARY_URL")
                .expect("DO_WORKER_BINARY_URL env var must be set for Worker mode");
            let ts_key = std::env::var("TAILSCALE_AUTH_KEY")
                .expect("TAILSCALE_AUTH_KEY env var must be set for Worker mode");
            let do_token = std::env::var("DIGITALOCEAN_TOKEN")
                .expect("DIGITALOCEAN_TOKEN env var must be set for Worker mode");
            let db_url = std::env::var("DATABASE_URL").unwrap_or_default();
            let scope_id = std::env::var("SCOPE_ID").unwrap_or_default();
            let interactsh_url = std::env::var("INTERACTSH_URL").unwrap_or_default();
            // INTERACTSH_SERVER_URL (bare host) is read by OobInteractionManager::new() inside the worker.
            // We derive it from INTERACTSH_URL by stripping the scheme, so the host only needs INTERACTSH_URL set.
            let interactsh_server_url = std::env::var("INTERACTSH_SERVER_URL")
                .unwrap_or_else(|_| {
                    interactsh_url
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/')
                        .to_string()
                });
            let interactsh_token = std::env::var("INTERACTSH_TOKEN").unwrap_or_default();
            let node_id = format!("do-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
            format!(r#"#cloud-config
package_update: true
packages:
  - nmap
  - masscan
  - curl
  - ca-certificates
write_files:
  - path: /usr/local/sbin/self-destruct.sh
    permissions: '0700'
    content: |
      #!/bin/sh
      # Self-destruct via DO API using metadata service droplet ID
      DROPLET_ID=$(curl -fsSL http://169.254.169.254/metadata/v1/id)
      curl -fsSL -X DELETE \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer {do_token}" \
        "https://api.digitalocean.com/v2/droplets/$DROPLET_ID" || true
      # Belt-and-suspenders: poweroff even if API call fails
      sleep 5
      poweroff -f
runcmd:
  - mkdir -p /usr/local/bin /var/lib/mimikri
  - curl -fsSL -o /usr/local/bin/redteam_rust_core {binary_url} || (echo "Binary download failed" && /usr/local/sbin/self-destruct.sh)
  - chmod 755 /usr/local/bin/redteam_rust_core
  - curl -fsSL https://tailscale.com/install.sh | sh
  - tailscale up --auth-key={ts_key} --hostname={node_id} --ephemeral --accept-routes=false --accept-dns=false --ssh=false
  - |
    cat > /etc/systemd/system/redteam-worker.service <<EOF
    [Unit]
    Description=Mimikri Worker
    After=network-online.target
    Wants=network-online.target
    [Service]
    Type=simple
    User=root
    Environment="DATABASE_URL={db_url}"
    Environment="RUST_LOG=info"
    Environment="SCOPE_ID={scope_id}"
    Environment="REDTEAM_AUTHORIZED_SCOPE={scope_id}"
    Environment="INTERACTSH_SERVER_URL={interactsh_server_url}"
    Environment="INTERACTSH_URL={interactsh_url}"
    Environment="INTERACTSH_TOKEN={interactsh_token}"
    ExecStart=/usr/local/bin/redteam_rust_core --worker --postgres-url {db_url} --node-id {node_id} --concurrency 4 --soft-mem-limit-mb 600
    Restart=no
    TimeoutStopSec=60s
    RuntimeMaxSec=21600
    ExecStopPost=/usr/local/sbin/self-destruct.sh
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectKernelLogs=yes
    ProtectControlGroups=yes
    LockPersonality=yes
    RestrictRealtime=yes
    ReadWritePaths=/var/lib/mimikri /tmp
    SystemCallArchitectures=native
    SystemCallFilter=@system-service
    AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
    CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
    MemoryMax=900M
    LimitNOFILE=8192
    [Install]
    WantedBy=multi-user.target
    EOF
  - systemctl daemon-reload
  - systemctl enable --now redteam-worker
"#)
        }
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

    pub async fn create_worker_droplet(&self, name: &str, region: &str) -> Result<Droplet> {
        if std::env::var("DO_WORKER_BINARY_URL").is_err() {
            anyhow::bail!("DO_WORKER_BINARY_URL env var is required to spawn worker droplets. Set it to the HTTPS URL of the pre-built x86_64 musl binary.");
        }
        self.create_droplet(name, region, ProxyMode::Worker).await
    }

    pub async fn create_droplet(&self, name: &str, region: &str, mode: ProxyMode) -> Result<Droplet> {
        let socks_user = "operator"; 
        let socks_pass = uuid::Uuid::new_v4().to_string()[..12].to_string();

        let mut ssh_keys = vec![];
        if let Ok(key) = std::env::var("DO_SSH_KEY_ID") {
            ssh_keys.push(key);
        }

        let size = if mode == ProxyMode::Worker {
            std::env::var("DO_DROPLET_SIZE").unwrap_or_else(|_| "s-1vcpu-1gb".to_string())
        } else {
            std::env::var("DO_DROPLET_SIZE").unwrap_or_else(|_| "s-1vcpu-512mb".to_string())
        };

        let request = CreateDropletRequest {
            name: name.to_string(),
            region: region.to_string(),
            size,
            image: "ubuntu-22-04-x64".to_string(),
            ssh_keys, 
            backups: false,
            ipv6: false,
            monitoring: true,
            tags: vec!["osint-ultimate".to_string(), "ephemeral".to_string()],
            user_data: Some(generate_user_data(mode, socks_user, &socks_pass)),
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

    /// Reaper: destroy droplets that are off or exceeded TTL (6h).
    pub async fn reap_stale_droplets(&self) -> Result<u32> {
        let droplets = self.list_droplets().await?;
        let mut destroyed = 0u32;
        let _now = chrono::Utc::now();
        for d in droplets {
            let should_destroy = d.status == "off" || {
                // If droplet has been active for > 6h, destroy it
                // DO API does not give created_at in this struct, so we rely on status=off
                // and a conservative kill. For TTL-based kill, see self-destruct.sh on the droplet.
                false
            };
            if should_destroy {
                info!("🛡️ REAPER: Destroying stale/off droplet {} (ID: {}, status: {})", d.name, d.id, d.status);
                if let Err(e) = self.destroy_droplet(d.id).await {
                    tracing::error!("❌ REAPER: Failed to destroy droplet {}: {}", d.id, e);
                } else {
                    destroyed += 1;
                }
            }
        }
        Ok(destroyed)
    }
}
