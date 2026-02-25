pub mod web;
pub mod net;
pub mod osint; 
pub mod ffi;

use async_trait::async_trait;
use crate::models::{TargetHost, Finding};
use anyhow::Result;

#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>>;
}

/// Trait for Discovery plugins (Stage 1 of the pipeline)
#[async_trait]
pub trait DiscoveryPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    /// Given a root target, returns an optional list of discovered sub-targets (e.g. subdomains)
    async fn discover(&self, target: &TargetHost) -> Result<Vec<String>>;
}
