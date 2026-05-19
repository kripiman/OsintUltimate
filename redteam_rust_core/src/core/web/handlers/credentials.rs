/// handlers/credentials.rs — Item 18 from PLAN v3 6.B mapping table.
/// pub async fn get_credentials (L457–L524)
use axum::{
    extract::State,
    Json,
};
use std::sync::Arc;

use super::super::state::{DashboardState, ValidatedOperator};
use super::super::models::CredentialStatus;

pub async fn get_credentials(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
) -> Json<Vec<CredentialStatus>> {
    use crate::utils::config::Config;
    let config = Config::from_env();

    let mut keys_refs: Vec<(&str, Option<&String>)> = vec![
        ("DigitalOcean", config.do_token.as_ref()),
        ("Shodan", config.shodan_api_key.as_ref()),
        ("HackerOne", config.h1_api_key.as_ref()),
        ("Bugcrowd", config.bugcrowd_api_key.as_ref()),
        ("Intigriti", config.intigriti_token.as_ref()),
        ("Netlas", config.netlas_api_key.as_ref()),
        ("SecurityTrails", config.securitytrails_api_key.as_ref()),
        ("MobSF", config.mobsf_api_key.as_ref()),
        ("OpenAI", config.openai_api_key.as_ref()),
        ("Anthropic", config.anthropic_api_key.as_ref()),
        ("Gemini", config.gemini_api_keys.as_ref()),
        ("Kimi", config.kimi_api_key.as_ref()),
        ("Antigravity", config.antigravity_api_key.as_ref()),
        ("Azure OpenAI", config.azure_openai_key.as_ref()),
    ];

    let claude_status_string = "Enabled".to_string();
    if config.claude_code_enabled {
        keys_refs.push(("Claude Code", Some(&claude_status_string)));
    } else {
        keys_refs.push(("Claude Code", None));
    }

    let mut results = Vec::new();
    for (name, key) in keys_refs {
        let mut display_name = name.to_string();
        if name == "Gemini" {
            if let Some(keys_str) = config.gemini_api_keys.as_ref() {
                let count = keys_str.split(',').filter(|k| !k.trim().is_empty()).count();
                if count > 1 {
                    display_name = format!("Gemini ({} keys)", count);
                }
            }
        }

        let mut status = if key.is_none() {
            "Not Added".to_string()
        } else {
            "Idle".to_string()
        };

        let mut last_check = None;
        let mut error = None;

        if let Some(tracked) = state.credentials.get(name) {
            status = tracked.status.clone();
            last_check = tracked.last_check.clone();
            error = tracked.error.clone();
        }

        results.push(CredentialStatus {
            service: display_name,
            status,
            last_check,
            error,
        });
    }

    Json(results)
}
