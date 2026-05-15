use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::models::findings::Finding;

/// Schema for findings spilled to disk or persistent queue during backpressure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpilledEvent {
    /// Schema version for forward/backward compatibility (e.g., 1 for V16.1)
    pub schema_version: u32,
    
    /// Precision timestamp of the event
    pub timestamp: DateTime<Utc>,
    
    /// Unique identifier for the multi-tenant scope
    pub scope_id: String,
    
    /// The finding itself (will be serialized as part of the NDJSON line)
    pub finding: Finding,
}

impl SpilledEvent {
    pub fn new(scope_id: String, finding: Finding) -> Self {
        Self {
            schema_version: 1,
            timestamp: Utc::now(),
            scope_id,
            finding,
        }
    }
}

// Logic for NDJSON (Newline Delimited JSON) handling will be implemented in Phase 2.
// This file serves as the SSOT for the serialization schema.
