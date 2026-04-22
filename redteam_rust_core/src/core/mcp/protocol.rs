use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

// MCP Tool definitions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallToolResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum McpContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "wenyan")]
    Wenyan { text: String },
}

// SSE Handshake types
#[derive(Debug, Serialize, Deserialize)]
pub struct McpInitializeRequest {
    pub protocol_version: String,
    pub capabilities: Value,
    pub client_info: Value,
}

pub const MCP_VERSION: &str = "2024-11-05";
