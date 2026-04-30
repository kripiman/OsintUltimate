use crate::core::validation::PocValidator;
use crate::utils::executor::ExecutorMode;
use crate::models::TargetHost;
use anyhow::{Context, Result};

impl<M: ExecutorMode> PocValidator<M> {
    #[allow(dead_code)]
    pub(crate) async fn execute_raw_payload(&self, payload: &str, _target: &TargetHost) -> Result<String> {
        let parts: Vec<String> = payload.split_whitespace().map(|s| s.to_string()).collect();
        if parts.is_empty() { anyhow::bail!("Empty payload."); }
        
        let binary = &parts[0];
        let args = parts[1..].to_vec();
        
        let output = self.executor.execute_and_wait(binary, args).await?;
        Ok(format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    }

    pub(crate) async fn execute_safe_command(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let params: serde_json::Value = serde_json::from_str(payload).context("Invalid PoC payload JSON")?;
        let binary = params["binary"].as_str().context("Missing binary")?;
        
        let target_ip = target.pinned_addr()?;
        
        let mut args = Vec::new();
        match binary {
            "nmap" => {
                args.push("-p".to_string());
                args.push(params["port"].to_string());
                if let Some(flags) = params["flags"].as_array() {
                    for f in flags { args.push(f.as_str().unwrap().to_string()); }
                }
                args.push(target_ip.to_string());
            },
            "curl" => {
                let path = params["path"].as_str().unwrap_or("/");
                if !self.policy.is_path_safe(path) { anyhow::bail!("Policy Block: Unsafe path in curl PoC"); }
                args.push("-I".to_string());
                args.push(format!("http://{}{}", target_ip, path));
            },
            "ping" => {
                args.extend(vec!["-c".to_string(), "3".to_string(), target_ip.to_string()]);
            },
            _ => anyhow::bail!("Policy Block: Binary not supported for SafeCommand strategy"),
        }

        let output = self.executor.execute_and_wait(binary, args).await?;
        Ok(format!("{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
    }

    pub(crate) async fn execute_tcp_check(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let port = payload.trim().parse::<u16>()?;
        let target_addr = target.pinned_addr()?;
        
        let pm = self.proxy_manager.as_ref()
            .context("V13 OPSEC Violation: TCP check requires ProxyManager in Sovereign Stealth mode.")?;
        
        let _ = pm.tcp_connect_proxied(target_addr, port).await?;
        Ok(format!("TCP Port {} is OPEN (Proxy Verified)", port))
    }

    pub(crate) async fn execute_icmp_ping(&self, target: &TargetHost) -> Result<String> {
        let target_addr = target.pinned_addr()?;
        let output = self.executor.execute_and_wait("ping", vec!["-c".to_string(), "3".to_string(), target_addr.to_string()]).await?;
        if output.status.success() { Ok("Ping success".into()) } else { Ok("Ping failed".into()) }
    }

    pub(crate) async fn execute_http(&self, payload: &str, target: &TargetHost) -> Result<String> {
        let target_ip = target.pinned_addr()?;
        if !self.policy.is_path_safe(payload) { anyhow::bail!("Policy Block: Unsafe path in HTTP PoC"); }
        
        let pm = self.proxy_manager.as_ref()
            .context("V13 OPSEC Violation: HTTP PoC requires ProxyManager in Sovereign Stealth mode.")?;
        
        let (_, client) = pm.get_client_fail_closed(&target.host)?;

        let res = client.get(format!("http://{}{}", target_ip, payload)).send().await?;
        Ok(format!("Status: {}\nBody: {}", res.status(), res.text().await?.chars().take(1000).collect::<String>()))
    }
}
