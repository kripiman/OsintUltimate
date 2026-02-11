pub mod web;
pub mod net;
pub mod osint; // Export new module

use async_trait::async_trait;
use crate::models::TargetHost;
use anyhow::Result;

#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &mut TargetHost) -> Result<()>;
}
