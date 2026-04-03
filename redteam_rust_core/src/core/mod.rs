pub mod orchestrator;
pub mod agent;
pub mod pipeline;
pub mod sink;
pub mod plugin_loader;
pub mod capability_layer;
pub mod approval_gate;
pub mod blackarch;
pub mod ai_cascade;
pub mod waf_evasion;
pub mod correlation;
pub mod web_server;
pub mod filter;
pub mod lock_free_sink;
pub mod native_scanner;
pub mod poc_validator;
pub mod swarm;
pub mod resource_manager;
pub mod sandbox;
pub mod mcp;
#[cfg(test)]
pub mod tests;

pub use orchestrator::Orchestrator;
pub use pipeline::{Pipeline, PipelineBuilder};
pub use sink::{DataSink, JsonlSink, SqliteSink};
pub use correlation::{CorrelationEngine, AttackGraph, AttackPath};
pub use filter::FalsePositiveFilter;
pub use poc_validator::PocValidator;

