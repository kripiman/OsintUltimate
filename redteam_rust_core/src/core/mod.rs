pub mod agent;
pub mod skills;
pub mod pipeline;
pub mod sink;
pub mod plugin_loader;
pub mod capability_layer;
pub mod approval_gate;
pub mod blackarch;
pub mod ai;
pub mod waf;
pub mod correlation;
pub mod web;
pub mod filter;
pub mod lock_free_sink;
pub mod native_scanner;
pub mod validation;
pub mod swarm;
pub mod resource_manager;
pub mod sandbox;
pub mod mcp;
pub mod source_analyzer;
pub mod factory;
pub mod engine;
pub mod c2;
pub mod policy;
pub mod middleware;
pub mod persistence;
pub mod orchestrator;
pub mod verification;
pub mod notifications;
pub mod selection;

#[cfg(test)]
pub mod tests;

pub use orchestrator::Orchestrator;
pub use pipeline::{Pipeline, PipelineBuilder};
pub use sink::{DataSink, JsonlSink, PostgresSink};
pub use correlation::{CorrelationEngine, AttackGraph, AttackPath};
pub use filter::FalsePositiveFilter;
pub use validation::PocValidator;

