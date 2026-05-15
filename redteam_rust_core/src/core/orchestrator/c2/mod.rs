use async_trait::async_trait;
use anyhow::Result;
use crate::models::TargetHost;
use serde::{Deserialize, Serialize};

pub mod sliver_proto;

#[cfg(feature = "sovereign")]
pub mod sliver_feedback;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionState {
    Staged,
    Deployed,
    Established,
    Sovereign, // mTLS Verified & Persistent
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Session {
    pub id: String,
    pub target: String,
    pub state: SessionState,
    pub last_checkin: chrono::DateTime<chrono::Utc>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct InfrastructureConfig {
    #[serde(alias = "sliver-ca-path", alias = "sliver_ca")]
    pub sliver_ca_path: Option<String>,
    #[serde(alias = "sliver-cert-path", alias = "sliver_cert")]
    pub sliver_cert_path: Option<String>,
    #[serde(alias = "sliver-key-path", alias = "sliver_key")]
    pub sliver_key_path: Option<String>,
    #[serde(alias = "sliver-server-addr", alias = "sliver_addr")]
    pub sliver_server_addr: Option<String>,
}

#[async_trait]
pub trait C2Operator: Send + Sync {
    
    /// Prepare the payload (Staged state)
    async fn prepare_payload(&self, target: &TargetHost) -> Result<String>;
    
    /// Deploy the payload (Deployed state - usually via another exploit)
    async fn deploy_payload(&self, target: &TargetHost, payload_path: &str) -> Result<()>;
    
    /// Verify the session (Established/Sovereign state)
    async fn verify_session(&self, target: &TargetHost) -> Result<SessionState>;
    
    /// Get active sessions
    async fn list_sessions(&self) -> Result<Vec<C2Session>>;
}

pub mod typestate {
    use super::*;
    use std::marker::PhantomData;

    pub struct Staged;
    pub struct Deployed;
    pub struct Established;
    pub struct Sovereign;

    pub struct SliverOperator<S> {
        pub state: PhantomData<S>,
        pub expected_fingerprint: Option<String>,
    }

    pub struct HavocOperator<S> {
        pub state: PhantomData<S>,
        pub expected_fingerprint: Option<String>,
    }

    impl<S> SliverOperator<S> {
        pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
            self.expected_fingerprint = Some(fingerprint);
            self
        }
    }

    impl<S> HavocOperator<S> {
        pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
            self.expected_fingerprint = Some(fingerprint);
            self
        }
    }

    impl SliverOperator<Staged> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn deploy(self) -> SliverOperator<Deployed> {
            SliverOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
        }
    }

    impl Default for SliverOperator<Staged> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SliverOperator<Deployed> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn establish(self) -> SliverOperator<Established> {
            SliverOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
        }
    }

    impl Default for SliverOperator<Deployed> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SliverOperator<Established> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn promote(self, actual_fingerprint: &str) -> Result<SliverOperator<Sovereign>, String> {
            if let Some(ref expected) = self.expected_fingerprint {
                if expected == actual_fingerprint {
                    Ok(SliverOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint })
                } else {
                    Err(format!("mTLS Fingerprint mismatch! Expected {}, got {}", expected, actual_fingerprint))
                }
            } else {
                Err("No expected fingerprint configured for Sovereign promotion".to_string())
            }
        }
    }

    impl Default for SliverOperator<Established> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SliverOperator<Sovereign> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }
    }

    impl Default for SliverOperator<Sovereign> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HavocOperator<Staged> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn deploy(self) -> HavocOperator<Deployed> {
            HavocOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
        }
    }

    impl Default for HavocOperator<Staged> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HavocOperator<Deployed> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn establish(self) -> HavocOperator<Established> {
            HavocOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
        }
    }

    impl Default for HavocOperator<Deployed> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HavocOperator<Established> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn promote(self, actual_fingerprint: &str) -> Result<HavocOperator<Sovereign>, String> {
            if let Some(ref expected) = self.expected_fingerprint {
                if expected == actual_fingerprint {
                    Ok(HavocOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint })
                } else {
                    Err(format!("Havoc mTLS Fingerprint mismatch! Expected {}, got {}", expected, actual_fingerprint))
                }
            } else {
                // If no fingerprint is configured, we allow promotion but mark it as a policy choice
                Ok(HavocOperator { state: PhantomData, expected_fingerprint: None })
            }
        }
    }

    impl Default for HavocOperator<Established> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HavocOperator<Sovereign> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }
    }

    impl Default for HavocOperator<Sovereign> {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infrastructure_config_parity() {
        // Test with legacy kebab-case flags (typical in CLI/ENV overrides)
        let json_kebab = r#"{
            "sliver-ca-path": "/etc/sliver/ca.crt",
            "sliver-cert-path": "/etc/sliver/operator.crt",
            "sliver-key-path": "/etc/sliver/operator.key",
            "sliver-server-addr": "10.0.0.1:31337"
        }"#;
        
        let config: InfrastructureConfig = serde_json::from_str(json_kebab).unwrap();
        assert_eq!(config.sliver_ca_path, Some("/etc/sliver/ca.crt".to_string()));
        assert_eq!(config.sliver_server_addr, Some("10.0.0.1:31337".to_string()));

        // Test with short snake_case aliases
        let json_short = r#"{
            "sliver_ca": "/tmp/ca.crt",
            "sliver_addr": "localhost:31337"
        }"#;
        
        let config_short: InfrastructureConfig = serde_json::from_str(json_short).unwrap();
        assert_eq!(config_short.sliver_ca_path, Some("/tmp/ca.crt".to_string()));
        assert_eq!(config_short.sliver_server_addr, Some("localhost:31337".to_string()));
    }
}
