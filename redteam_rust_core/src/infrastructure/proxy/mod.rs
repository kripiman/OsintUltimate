pub mod types;
pub mod manager;
pub mod health;
pub mod managed_exit;
pub mod kill_switch;
pub mod fingerprint;
pub mod wrap_cmd;
pub mod builder;

pub use types::{ProxyConfig, ManagedExit};
pub use manager::ProxyManager;

// Re-export constants
pub use manager::MAX_LATENCY_SAMPLES;
