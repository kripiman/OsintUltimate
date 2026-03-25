pub mod orchestrator;
pub mod agent;
pub mod pipeline;
pub mod sink;
pub mod plugin_loader;
pub mod capability_layer;
pub mod approval_gate;
pub mod blackarch;
pub mod ai_cascade;
#[cfg(test)]
pub mod tests;

pub use orchestrator::Orchestrator;
pub use pipeline::{Pipeline, PipelineBuilder};
pub use sink::{DataSink, JsonlSink, SqliteSink};
