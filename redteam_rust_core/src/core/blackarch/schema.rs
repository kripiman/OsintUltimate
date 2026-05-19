use crate::plugins::Capability;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackArchTool {
    pub name: String,
    pub category: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub tool_name: String,
    pub version: Option<String>,
    pub synopsis: String,
    pub flags: Vec<FlagSchema>,
    pub output_formats: Vec<String>,
    pub resource_cost: ResourceCost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagSchema {
    pub short: Option<String>,
    pub long: Option<String>,
    pub description: String,
    pub takes_value: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResourceCost {
    Light,
    Medium,
    Heavy,
}
