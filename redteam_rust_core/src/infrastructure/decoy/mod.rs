pub mod config;
pub mod models;
pub mod controller;
pub mod persistence;

pub use config::DecoyConfig;
pub use models::{DecoyRecord, TripwireEvent};
pub use controller::DecoyController;
pub use persistence::spawn_tripwire_persister;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_decoy_config_validation_empty_domain() {
        let config = DecoyConfig {
            domain: String::new(),
            canary_subdomains: vec!["test".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_decoy_config_validation_no_subdomains() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec![],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_decoy_config_validation_valid() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec!["admin-panel".to_string(), "vpn-portal".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_decoy_config_validation_invalid_domain() {
        let config = DecoyConfig {
            domain: "nodotdomain".to_string(),
            canary_subdomains: vec!["test".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tripwire_event_serialization() {
        let event = TripwireEvent {
            fqdn: "admin.example.me".to_string(),
            source_ip: "203.0.113.42".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            headers_json: r#"{"Host":"admin.example.me"}"#.to_string(),
            triggered_at: Utc::now(),
            ja3_hash: Some("abc123def456".to_string()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TripwireEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fqdn, "admin.example.me");
        assert_eq!(deserialized.source_ip, "203.0.113.42");
    }

    #[test]
    fn test_tripwire_to_finding() {
        let event = TripwireEvent {
            fqdn: "vpn.example.me".to_string(),
            source_ip: "198.51.100.1".to_string(),
            method: "HEAD".to_string(),
            path: "/login".to_string(),
            user_agent: None,
            headers_json: "{}".to_string(),
            triggered_at: Utc::now(),
            ja3_hash: None,
        };

        let finding = DecoyController::tripwire_to_finding(&event);
        assert_eq!(finding.category, crate::models::Category::Recon);
        assert_eq!(finding.severity, crate::models::Severity::Critical);
        assert!(finding.description.contains("vpn.example.me"));
        assert!(finding.description.contains("198.51.100.1"));
    }

    #[test]
    fn test_controller_creation() {
        let config = DecoyConfig {
            domain: "example.me".to_string(),
            canary_subdomains: vec!["admin".to_string()],
            cloudflare_zone_id: "zone123".to_string(),
            cloudflare_api_token: "token123".to_string(),
            callback_ip: "1.2.3.4".to_string(),
            max_listener_connections: 10,
        };

        let pm = std::sync::Arc::new(crate::utils::proxy::ProxyManager::new(Vec::new(), true, crate::utils::config::ProxyMode::Dante, 10));
        let (controller, _rx) = DecoyController::new(config, pm).unwrap();
        assert_eq!(controller.active_count(), 0);
        assert!(controller.list_active().is_empty());
    }
}
