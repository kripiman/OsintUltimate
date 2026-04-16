use axum::{
    extract::{State, Path},
    response::{sse::{Event, Sse}, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, error};
use serde_json::json;

use crate::core::mcp::protocol::{JsonRpcRequest, CallToolRequest, CallToolResult, McpContent};
use crate::plugins::GlobalConfig;
use crate::core::mcp::sanitizer::DataSanitizer;
use crate::core::ai::compressor::ContextCompressor;
use crate::core::ai::types::RouteLevel;

use crate::core::sink::SqliteSink;
use std::path::PathBuf;
use moka::future::Cache;

pub struct McpServer {
    config: Arc<GlobalConfig>,
    sanitizer: Arc<DataSanitizer>,
    sessions: Arc<dashmap::DashMap<String, mpsc::Sender<Event>>>,
    db: Option<Arc<SqliteSink>>,
    plugin_cache: Cache<String, String>,
}

impl McpServer {
    pub fn new(config: GlobalConfig) -> Self {
        let plugin_cache = Cache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_secs(1800)) // 30 min TTL
            .build();

        Self {
            config: Arc::new(config),
            sanitizer: Arc::new(DataSanitizer::new()),
            sessions: Arc::new(dashmap::DashMap::new()),
            db: None,
            plugin_cache,
        }
    }

    pub async fn with_sqlite(mut self, path: PathBuf) -> Self {
        if let Ok(db) = SqliteSink::new(path).await {
            self.db = Some(Arc::new(db));
        }
        self
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
    Path(_session_id): Path<String>,
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

    // 1.1 CACHÉ PERSISTENTE (Fase 2 Roadmap)
    let cache_key = format!("{}:{}", plugin_name, target_real);
    
    // Nivel 1: Moka (RAM)
    if let Some(cached) = state.plugin_cache.get(&cache_key) {
        info!("🚀 [MCP-CACHE] Hit en RAM (Moka) para: {}", cache_key);
        return json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("[CACHED: RAM] {}", cached) }],
            is_error: false
        });
    }

    // Nivel 2: SQLite (Disco)
    if let Some(ref db) = state.db {
        if let Ok(Some(cached)) = db.load_plugin_cache(&cache_key).await {
            info!("💾 [MCP-CACHE] Hit en Disco (SQLite) para: {}", cache_key);
            // Re-poblar RAM
            state.plugin_cache.insert(cache_key.clone(), cached.clone()).await;
            return json!(CallToolResult {
                content: vec![McpContent::Text { text: format!("[CACHED: DISK] {}", cached) }],
                is_error: false
            });
        }
    }

    // 2. BUSCAR PLUGIN
    let registry = crate::plugins::get_registry((*state.config).clone());
    let plugin = registry.scanners.iter().find(|p| p.name() == plugin_name);

    if let Some(p) = plugin {
        let host = crate::models::TargetHost {
            host: target_real.clone(),
            ip: None, // El plugin lo resolverá si es necesario
            resolved_ip: None,
            status: crate::models::TargetStatus::Scanning,
            target_type: crate::models::TargetType::Network,
            user: None, // Auto-detect later or assume net
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        match p.scan(&host).await {
            Ok(findings) => {
                // 3. COMPRESIÓN DE CONTEXTO (Integración V14.1)
                // Usamos el ContextCompressor para minificar los findings y ahorrar tokens
                let compressed_findings: Vec<_> = findings.iter()
                    .map(|f| ContextCompressor::compress_finding(f, RouteLevel::Local))
                    .collect();

                let summary = if compressed_findings.is_empty() {
                    "No se encontraron hallazgos relevantes.".to_string()
                } else {
                    serde_json::to_string_pretty(&compressed_findings).unwrap_or_default()
                };

                // 4. FILTRADO SEMÁNTICO Y SCRUBBING (BlackArch Rules)
                let filtered = state.sanitizer.filter_tool_output(plugin_name, &summary);

                // 5. MASCARAR SALIDA (Real -> IA)
                let final_text = state.sanitizer.mask_output(&filtered);

                // 5.1 GUARDAR EN CACHÉ (Fase 2 Roadmap)
                state.plugin_cache.insert(cache_key.clone(), final_text.clone()).await;
                if let Some(ref db) = state.db {
                    let _ = db.save_plugin_cache(&cache_key, &final_text).await;
                }

                // 6. LOGS Y MÉTRICAS (Fase 5 Roadmap)
                let original_len = summary.len();
                let filtered_len = filtered.len();
                let savings = if original_len > 0 {
                    (1.0 - (filtered_len as f64 / original_len as f64)) * 100.0
                } else {
                    0.0
                };
                info!("📊 [MCP-STATS] Plugin: {} | Original: {} chars | Filtered: {} chars | Ahorro: {:.2}%", 
                    plugin_name, original_len, filtered_len, savings);

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
