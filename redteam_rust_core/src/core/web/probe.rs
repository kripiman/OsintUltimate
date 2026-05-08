use std::sync::Arc;
use tokio::time::{sleep, Duration};
use crate::core::web::state::DashboardState;
use crate::core::web::models::CredentialStatus;
use crate::utils::config::Config;
use tracing::{info, warn};

pub async fn start_credential_prober(state: Arc<DashboardState>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Mimikri-Health-Probe/1.0")
        .build()
        .expect("HTTP client must build for prober (check SSL/OpenSSL libs)");

    let config = Config::from_env();
    loop {
        info!("🔍 CREDENTIALS: Starting periodic API health probe...");
        
        // 1. Shodan
        if let Some(key) = &config.shodan_api_key {
            let url = format!("https://api.shodan.io/api-info?key={}", key);
            let res = client.get(&url).send().await;
            update_status(&state, "Shodan", res).await;
        }

        // 2. DigitalOcean
        if let Some(token) = &config.do_token {
            let res = client.get("https://api.digitalocean.com/v2/account")
                .header("Authorization", format!("Bearer {}", token))
                .send().await;
            update_status(&state, "DigitalOcean", res).await;
        }

        // 3. HackerOne
        if let (Some(user), Some(key)) = (&config.h1_username, &config.h1_api_key) {
            let res = client.get("https://api.hackerone.com/v1/me")
                .basic_auth(user, Some(key))
                .send().await;
            update_status(&state, "HackerOne", res).await;
        } else if config.h1_api_key.is_some() {
            warn!("⚠️ CREDENTIALS: H1_API_KEY set but H1_USERNAME missing. HackerOne probe skipped.");
        }

        // 4. Bugcrowd (Note: Token should be 'email:token' or just 'token' depending on version)
        if let Some(key) = &config.bugcrowd_api_key {
            let res = client.get("https://api.bugcrowd.com/programs")
                .header("Authorization", format!("Token {}", key))
                .header("Accept", "application/vnd.bugcrowd.v4+json")
                .send().await;
            update_status(&state, "Bugcrowd", res).await;
        }

        // 5. Intigriti
        if let Some(token) = &config.intigriti_token {
            let res = client.get("https://api.intigriti.com/external/researcher/v1/programs")
                .header("Authorization", format!("Bearer {}", token))
                .send().await;
            update_status(&state, "Intigriti", res).await;
        }

        // 6. Netlas
        if let Some(key) = &config.netlas_api_key {
            let res = client.get("https://app.netlas.io/api/indices/")
                .header("X-API-Key", key)
                .send().await;
            update_status(&state, "Netlas", res).await;
        }

        // 7. SecurityTrails
        if let Some(key) = &config.securitytrails_api_key {
            let res = client.get("https://api.securitytrails.com/v1/ping")
                .header("APIKEY", key)
                .send().await;
            update_status(&state, "SecurityTrails", res).await;
        }

        // 8. MobSF
        if let (Some(url), Some(key)) = (&config.mobsf_url, &config.mobsf_api_key) {
            let endpoint = format!("{}/api/v1/scans", url.trim_end_matches('/'));
            let res = client.get(&endpoint)
                .header("Authorization", key)
                .send().await;
            update_status(&state, "MobSF", res).await;
        }

        // 9. OpenAI
        if let Some(key) = &config.openai_api_key {
            let res = client.get("https://api.openai.com/v1/models")
                .header("Authorization", format!("Bearer {}", key))
                .send().await;
            update_status(&state, "OpenAI", res).await;
        }

        // 10. Anthropic
        if let Some(key) = &config.anthropic_api_key {
            let res = client.get("https://api.anthropic.com/v1/models")
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .send().await;
            update_status(&state, "Anthropic", res).await;
        }

        // 11. Gemini (Pool Health Check)
        if let Some(keys_str) = &config.gemini_api_keys {
            let keys: Vec<&str> = keys_str.split(',').filter(|k| !k.trim().is_empty()).collect();
            let mut all_ok = true;
            let mut errors = Vec::new();
            
            for (i, key) in keys.iter().enumerate() {
                let res = client.get(format!("https://generativelanguage.googleapis.com/v1beta/models?key={}", key))
                    .send().await;
                
                match res {
                    Ok(r) if r.status().is_success() => {},
                    Ok(r) => {
                        all_ok = false;
                        errors.push(format!("Key #{}: HTTP {}", i+1, r.status()));
                    },
                    Err(e) => {
                        all_ok = false;
                        errors.push(format!("Key #{}: {}", i+1, e));
                    }
                }
            }

            let now = chrono::Utc::now().to_rfc3339();
            let status = if all_ok {
                CredentialStatus {
                    service: "Gemini".to_string(),
                    status: "Working".to_string(),
                    last_check: Some(now),
                    error: None,
                }
            } else {
                CredentialStatus {
                    service: "Gemini".to_string(),
                    status: "Partial Failure".to_string(),
                    last_check: Some(now),
                    error: Some(errors.join(" | ")),
                }
            };
            state.credentials.insert("Gemini".to_string(), status);
        }

        // 12. Kimi (Moonshot)
        if let Some(key) = &config.kimi_api_key {
            let res = client.get("https://api.moonshot.cn/v1/models")
                .header("Authorization", format!("Bearer {}", key))
                .send().await;
            update_status(&state, "Kimi", res).await;
        }

        // 13. Antigravity
        if let (Some(key), Some(endpoint)) = (&config.antigravity_api_key, &config.antigravity_endpoint) {
            let res = client.get(format!("{}/v1/models", endpoint.trim_end_matches('/')))
                .header("Authorization", format!("Bearer {}", key))
                .send().await;
            update_status(&state, "Antigravity", res).await;
        }

        // 14. Azure OpenAI
        if let (Some(key), Some(endpoint)) = (&config.azure_openai_key, &config.azure_openai_endpoint) {
            let url = format!("{}/openai/models?api-version=2024-10-21", endpoint.trim_end_matches('/'));
            let res = client.get(&url)
                .header("api-key", key)
                .send().await;
            update_status(&state, "Azure OpenAI", res).await;
        }

        // 15. Claude Code (Check binary in PATH)
        if config.claude_code_enabled {
            let res = tokio::process::Command::new("claude")
                .arg("--version")
                .output()
                .await;
            
            let status = match res {
                Ok(out) if out.status.success() => {
                    let now = chrono::Utc::now().to_rfc3339();
                    super::models::CredentialStatus {
                        service: "Claude Code".to_string(),
                        status: "Working".to_string(),
                        last_check: Some(now),
                        error: None,
                    }
                },
                Ok(out) => {
                    let now = chrono::Utc::now().to_rfc3339();
                    super::models::CredentialStatus {
                        service: "Claude Code".to_string(),
                        status: "Failed".to_string(),
                        last_check: Some(now),
                        error: Some(format!("Exit code {}", out.status.code().unwrap_or(-1))),
                    }
                },
                Err(e) => {
                    let now = chrono::Utc::now().to_rfc3339();
                    super::models::CredentialStatus {
                        service: "Claude Code".to_string(),
                        status: "Failed".to_string(),
                        last_check: Some(now),
                        error: Some(format!("Binary not found: {}", e)),
                    }
                }
            };
            state.credentials.insert("Claude Code".to_string(), status);
        }

        info!("✅ CREDENTIALS: Probe cycle complete.");
        sleep(Duration::from_secs(1800)).await; // 30 mins (Save Shodan/API quotas)
    }
}

async fn update_status(state: &DashboardState, service: &str, res: Result<reqwest::Response, reqwest::Error>) {
    let now = chrono::Utc::now().to_rfc3339();
    let status = match res {
        Ok(r) => {
            let status_code = r.status();
            if status_code.is_success() {
                CredentialStatus {
                    service: service.to_string(),
                    status: "Working".to_string(),
                    last_check: Some(now),
                    error: None,
                }
            } else {
                let err_msg = match status_code.as_u16() {
                    401 => "Unauthorized (Invalid Key)".to_string(),
                    403 => "Forbidden (Permission Denied)".to_string(),
                    429 => "Rate Limited / Quota Exceeded".to_string(),
                    code => format!("HTTP Error {}", code),
                };
                CredentialStatus {
                    service: service.to_string(),
                    status: "Failed".to_string(),
                    last_check: Some(now),
                    error: Some(err_msg),
                }
            }
        },
        Err(e) => {
            warn!("⚠️ CREDENTIALS: Connection error probing {}: {}", service, e);
            CredentialStatus {
                service: service.to_string(),
                status: "Failed".to_string(),
                last_check: Some(now),
                error: Some(format!("Network Error: {}", e)),
            }
        }
    };
    state.credentials.insert(service.to_string(), status);
}
