use async_trait::async_trait;
use anyhow::Result;
use crate::models::{TargetHost, Finding};
use serde::{Deserialize, Serialize};

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
    pub struct Staged;
    pub struct Deployed;
    pub struct Established;
    pub struct Sovereign;

    pub struct SliverOperator<S> {
        pub state: std::marker::PhantomData<S>,
        // Add common fields here
    }

    impl SliverOperator<Staged> {
        pub fn new() -> Self {
            Self { state: std::marker::PhantomData }
        }
    }
}
