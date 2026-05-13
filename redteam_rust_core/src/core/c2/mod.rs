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

    impl SliverOperator<Deployed> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn establish(self) -> SliverOperator<Established> {
            SliverOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
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

    impl SliverOperator<Sovereign> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
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

    impl HavocOperator<Deployed> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }

        pub fn establish(self) -> HavocOperator<Established> {
            HavocOperator { state: PhantomData, expected_fingerprint: self.expected_fingerprint }
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

    impl HavocOperator<Sovereign> {
        pub fn new() -> Self {
            Self { state: PhantomData, expected_fingerprint: None }
        }
    }
}
