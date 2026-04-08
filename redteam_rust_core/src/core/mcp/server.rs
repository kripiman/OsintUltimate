use axum::{
    extract::{State, Path},
    response::{sse::{Event, Sse}, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, collections::HashMap, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, error, warn};
use serde_json::json;

use crate::core::mcp::protocol::{JsonRpcRequest, JsonRpcResponse, CallToolRequest, CallToolResult, McpContent};
use crate::plugins::GlobalConfig;
use crate::core::mcp::sanitizer::DataSanitizer;

pub struct McpServer {
    config: Arc<GlobalConfig>,
    sanitizer: Arc<DataSanitizer>,
    sessions: Arc<dashmap::DashMap<String, mpsc::Sender<Event>>>,
}

impl McpServer {
    pub fn new(config: GlobalConfig) -> Self {
        Self {
            config: Arc::new(config),
            sanitizer: Arc::new(DataSanitizer::new()),
            sessions: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub async fn run(self, port: u16) -> anyhow::Result<()> {
        let state = Arc::new(self);
        
        let app = Router::new()
            .route("/sse", get(sse_handler))
            .route("/message/:session_id", post(message_handler))
            .with_state(state);

        let addr = format!("127.0.0.1:{}", port);
        info!("🛡️ [MCP-Server] Escuchando en http://{} (SSE Enabled)", addr);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

async fn sse_handler(
    State(state): State<Arc<McpServer>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = mpsc::channel(100);
    
    state.sessions.insert(session_id.clone(), tx.clone());
    
    // El cliente MCP necesita conocer su endpoint de mensajes
    let _ = tx.send(Event::default().event("endpoint").data(format!("/message/{}", session_id))).await;

    let stream = ReceiverStream::new(rx).map(Ok);

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

async fn message_handler(
    State(state): State<Arc<McpServer>>,
    Path(session_id): Path<String>,
    Json(payload): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let response = match payload.method.as_str() {
        "initialize" => json!({
            "protocolVersion": crate::core::mcp::protocol::MCP_VERSION,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": "OsintUltimate-MCP",
                "version": "4.0.0"
            }
        }),
        "tools/list" => {
            let registry = crate::plugins::get_registry((*state.config).clone()); // Clone inner for usage
            let plugin_names: Vec<String> = registry.scanners.iter().map(|p| p.name().to_string()).collect();
            
            // SUPER-TOOL ÚNICA para ahorro de tokens
            json!({
                "tools": [
                    {
                        "name": "osint_execute_plugin",
                        "description": "Ejecuta herramientas profesionales de Pentesting/OSINT sobre un objetivo. Usa este comando para realizar escaneos de red, auditorías web y explotación.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "target": {
                                    "type": "string",
                                    "description": "El objetivo (IP o Dominio). Usa los descriptores REDACTED si ya los conoces."
                                },
                                "plugin_name": {
                                    "type": "string",
                                    "enum": plugin_names,
                                    "description": "El plugin de seguridad específico a ejecutar."
                                }
                            },
                            "required": ["target", "plugin_name"]
                        }
                    }
                ]
            })
        },
        "tools/call" => {
            if let Some(params) = payload.params {
                let call: CallToolRequest = serde_json::from_value(params).unwrap();
                if call.name == "osint_execute_plugin" {
                    handle_execute_plugin(&state, call.arguments).await
                } else {
                    json!({"error": {"code": -32601, "message": "Tool not found"}})
                }
            } else {
                json!({"error": {"code": -32602, "message": "Invalid params"}})
            }
        }
        _ => json!({"error": {"code": -32601, "message": "Method not found"}}),
    };

    let full_response = json!({
        "jsonrpc": "2.0",
        "id": payload.id,
        "result": response
    });

    Json(full_response)
}

async fn handle_execute_plugin(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let target_masked = args["target"].as_str().unwrap_or("");
    let plugin_name = args["plugin_name"].as_str().unwrap_or("");

    // 1. DESENMASCARAR (IA -> Real)
    let target_real = state.sanitizer.unmask_input(target_masked);
    info!("🛡️ [MCP-OPSEC] Interpolando '{}' -> Real: '{}'", target_masked, target_real);

    // 2. BUSCAR PLUGIN
    let registry = crate::plugins::get_registry((*state.config).clone());
    let plugin = registry.scanners.iter().find(|p| p.name() == plugin_name);

    if let Some(p) = plugin {
        let host = crate::models::TargetHost {
            host: target_real.clone(),
            ip: None, // El plugin lo resolverá si es necesario
            resolved_ip: None,
            status: crate::models::TargetStatus::Scanning,
            target_type: crate::models::TargetType::Network, // Auto-detect later or assume net
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        match p.scan(&host).await {
            Ok(findings) => {
                // 3. COMPRESIÓN DE CONTEXTO Y RESUMEN
                let mut summary = String::new();
                for f in findings {
                    summary.push_str(&format!("- [{}]: {}\n", f.severity.to_string(), f.title));
                }
                
                if summary.is_empty() {
                    summary = "No se encontraron hallazgos relevantes.".to_string();
                }

                // 4. MASCARAR SALIDA (Real -> IA)
                let final_text = state.sanitizer.mask_output(&summary);

                json!(CallToolResult {
                    content: vec![McpContent::Text { text: final_text }],
                    is_error: false
                })
            }
            Err(e) => {
                error!("Error ejecutando plugin {} en MCP: {}", plugin_name, e);
                json!(CallToolResult {
                    content: vec![McpContent::Text { text: format!("Error de ejecución: {}", e) }],
                    is_error: true
                })
            }
        }
    } else {
        json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("Plugin '{}' no encontrado.", plugin_name) }],
            is_error: true
        })
    }
}
