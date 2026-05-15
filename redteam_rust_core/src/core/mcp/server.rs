use axum::{
    extract::{Path, State, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, sse::{Event, Sse}},
    routing::{get, post},
    Json, Router,
};
use axum::async_trait;
use tower_http::cors::{AllowOrigin, CorsLayer};
// use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer, errors::display_error};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, error, warn};
use serde_json::json;
use sha2::{Sha256, Digest};
use hex::ToHex;

use crate::core::mcp::protocol::{JsonRpcRequest, CallToolRequest, CallToolResult, McpContent};
use crate::plugins::GlobalConfig;
use crate::core::mcp::sanitizer::DataSanitizer;
use crate::core::ai::compressor::ContextCompressor;
use crate::core::ai::types::RouteLevel;
use crate::core::ai::{PROMPT_OPTIMIZER};
use crate::core::ai::token_optimizer::PromptOptimizer;

use crate::core::sink::PostgresSink;
use crate::utils::tone::{tone_encode, tonl_encode, to_ascii_safe};
use std::path::PathBuf;
use moka::future::Cache;
use dashmap::DashMap;

pub struct McpServer {
    pub(crate) config: Arc<GlobalConfig>,
    pub(crate) sanitizer: Arc<DataSanitizer>,
    pub(crate) sessions: Arc<dashmap::DashMap<String, mpsc::Sender<Event>>>,
    pub(crate) db: Option<Arc<PostgresSink>>,
    pub(crate) plugin_cache: Cache<String, String>,
    // Delta cache: SHA-256 de archivos leídos para smart_file_read
    file_hash_cache: Arc<DashMap<String, String>>,
    // Loop detection: historial de (tool, input_hash) — últimas 20 llamadas
    call_history: Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    // Checkpoint Manifest: Registro de snapshots para continuidad
    checkpoint_manifest: Arc<DashMap<String, serde_json::Value>>,

    // PHASE 5: Métricas de Sesión Optimizadas (Atomics)
    pub total_calls: AtomicU32,
    pub cache_hits: AtomicU32,
    pub tokens_saved: AtomicU64,
    pub bytes_processed: AtomicU64,
    /// V14.6: WAF AI engine reference for LSH/inference metrics in stats
    pub off_path_engine: Option<Arc<crate::core::ai::off_path::OffPathAiEngine>>,
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
            file_hash_cache: Arc::new(DashMap::new()),
            call_history: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(20))),
            checkpoint_manifest: Arc::new(DashMap::new()),
            total_calls: AtomicU32::new(0),
            cache_hits: AtomicU32::new(0),
            tokens_saved: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            off_path_engine: None,
        }
    }

    pub async fn with_postgres(mut self, path: PathBuf) -> Self {
        if let Ok(db) = PostgresSink::new(path).await {
            // Cargar métricas históricas de la base de datos
            let stats_res: anyhow::Result<std::collections::HashMap<String, i64>> = db.get_mcp_stats().await;
            if let Ok(stats) = stats_res {
                if let Some(v) = stats.get("total_calls") { self.total_calls.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("cache_hits") { self.cache_hits.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("tokens_saved") { self.tokens_saved.store(*v as u64, Ordering::SeqCst); }
                if let Some(v) = stats.get("bytes_processed") { self.bytes_processed.store(*v as u64, Ordering::SeqCst); }
            }
            self.db = Some(Arc::new(db));
        }
        self
    }

    /// V14.6: Attach the WAF off-path AI engine for LSH/inference metrics in stats.
    pub fn with_off_path_engine(mut self, engine: Arc<crate::core::ai::off_path::OffPathAiEngine>) -> Self {
        self.off_path_engine = Some(engine);
        self
    }

    pub async fn run(self, port: u16) -> anyhow::Result<()> {
        // Enforce MCP_TOKEN requirement (Sprint 1 - Fail-Closed)
        if self.config.mcp_token.is_none() || self.config.mcp_token.as_ref().unwrap().is_empty() {
            anyhow::bail!("CRITICAL: MCP_TOKEN not set in environment. MCP server cannot start without authentication.");
        }

        let state = Arc::new(self);
        
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, _| {
                let origin_str = origin.to_str().unwrap_or("");
                // Sprint 2: Exact matching including port to prevent subdomain hijacking/rebinding
                origin_str == format!("http://127.0.0.1:{}", port) || origin_str == format!("http://localhost:{}", port)
            }))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]);

/*
        // Rate limiting: 100 requests per second for MCP (IA can be noisy)
        let governor_conf = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(100)
                .burst_size(200)
                .error_handler(|e| {
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        display_error(e),
                    ).into_response()
                })
                .finish()
                .unwrap(),
        );
*/

        let app = Router::new()
            .route("/sse", get(sse_handler))
            .route("/message/:session_id", post(message_handler))
            // .layer(GovernorLayer::new(governor_conf))
            .layer(cors)
            .with_state(state);

        let addr = format!("127.0.0.1:{}", port);
        info!("🛡️ [MCP-Server] Escuchando en http://{} (SSE Enabled + AUTH + CORS Hardened)", addr);
        
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
}

pub struct ValidatedOperator;

#[async_trait]
impl FromRequestParts<Arc<McpServer>> for ValidatedOperator {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<McpServer>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid Authorization header format".to_string()));
        }

        let token = &auth_header[7..];
        
        if let Some(valid_token) = &state.config.mcp_token {
            if token == valid_token {
                return Ok(ValidatedOperator);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Invalid MCP token".to_string()))
    }
}

/// Helper para sanitizar y validar rutas dentro del workspace (Sprint 2)
fn validate_path(path_str: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::Path::new(path_str);
    
    // 1. Obtener la ruta base del workspace (CWD)
    let workspace_root = std::env::current_dir()
        .map_err(|e| format!("No se pudo determinar el workspace: {}", e))?;
    let workspace_root = std::fs::canonicalize(workspace_root)
        .map_err(|e| format!("No se pudo canonicalizar el workspace: {}", e))?;

    // 2. Canonicalizar la ruta objetivo (o su padre si no existe)
    let target_path = if path.exists() {
        std::fs::canonicalize(path)
            .map_err(|e| format!("Error de canonicalizacion: {}", e))?
    } else {
        let parent = path.parent().ok_or("Ruta sin directorio padre.".to_string())?;
        if parent.as_os_str().is_empty() {
             // Si el path es relativo simple "backup.md", el padre es "" (CWD)
             workspace_root.clone()
        } else {
            std::fs::canonicalize(parent)
                .map_err(|e| format!("El directorio padre no existe o no es accesible: {}", e))?
        }
    };

    // 3. Verificar que reside dentro del workspace
    if !target_path.starts_with(&workspace_root) {
        return Err(format!("PATH VIOLATION: '{}' fuera del workspace autorizado.", path_str));
    }

    Ok(path.to_path_buf())
}

async fn sse_handler(
    State(state): State<Arc<McpServer>>,
    _auth: ValidatedOperator,
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
    _auth: ValidatedOperator,
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
                "name": "Mimikri-MCP",
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
                                },
                                "support_tone": {
                                    "type": "boolean",
                                    "description": "Indica si el cliente soporta el formato denso TONE. Recomendado para ahorrar tokens."
                                },
                                "support_wenyan": {
                                    "type": "boolean",
                                    "description": "Indica si el cliente (IA-IA) soporta el protocolo Wenyan para compresión extrema."
                                },
                                "support_tonl": {
                                    "type": "boolean",
                                    "description": "Activa TONL V1.1: formato denso con diccionario global de claves. Superior a TONE V1 para findings con claves repetidas."
                                }
                            },
                            "required": ["target", "plugin_name"]
                        }
                    },
                    {
                        "name": "osint_compress_memory_file",
                        "description": "GAP-4: Comprime archivos de sesión (MEMORIA.md, HISTORIAL.md) usando PromptOptimizer para liberar tokens de contexto.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Ruta absoluta al archivo .md o .txt a comprimir."
                                },
                                "level": {
                                    "type": "string",
                                    "enum": ["lite", "full", "ultra"],
                                    "description": "Nivel de intensidad de la compresión."
                                }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "mcp_get_stats",
                        "description": "Retorna estadísticas de eficiencia del MCP (ahorro de tokens, tasa de caché, etc.). Úsalo para informar al usuario sobre el rendimiento del sistema.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "osint_detect_waste",
                        "description": "Analiza la sesión en busca de patrones de desperdicio de tokens y retorna un Quality Score (1-10).",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "osint_smart_read",
                        "description": "Lee un archivo de forma inteligente. Si el contenido no cambió desde la última lectura, retorna '[NO-CHANGE]' ahorrando todos los tokens del archivo. Si cambió, retorna solo el delta (líneas modificadas).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Ruta absoluta al archivo a leer."
                                }
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "osint_route_task",
                        "description": "Determina el modelo de IA optimo para una tarea basandose en el tamano del contexto y la naturaleza de la tarea. Usa esto antes de llamar a cualquier LLM para maximizar calidad y minimizar costo. Umbrales: >80k tokens -> Antigravity (Gemini), security/audit <30k -> Claude Code, resto -> Kimi.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "task": {
                                    "type": "string",
                                    "description": "Descripcion breve de la tarea (ej: 'security audit proxy module', 'global repo snapshot')."
                                },
                                "context_tokens": {
                                    "type": "integer",
                                    "description": "Estimacion de tokens del contexto a enviar al LLM."
                                },
                                "files": {
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Rutas de archivos involucrados en la tarea."
                                }
                            },
                            "required": ["task"]
                        }
                    },
                    {
                        "name": "osint_checkpoint_save",
                        "description": "Guarda un checkpoint de la sesión con semanticDigest (SHA-256) para continuidad operacional.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "trigger": { "type": "string", "description": "Evento que dispara el checkpoint (p.ej. 'pre-fanout')." },
                                "content": { "type": "string", "description": "Contenido semántico a preservar." }
                            },
                            "required": ["trigger", "content"]
                        }
                    }
                ]
            })
        },
        "tools/call" => {
            if let Some(params) = payload.params {
                match serde_json::from_value::<CallToolRequest>(params) {
                    Ok(call) => match call.name.as_str() {
                        "osint_route_task" => handle_route_task(call.arguments).await,
                        "osint_execute_plugin" => handle_execute_plugin(&state, call.arguments).await,
                        "osint_compress_memory_file" => handle_compress_memory(&state, call.arguments).await,
                        "mcp_get_stats" => handle_get_stats(&state).await,
                        "osint_detect_waste" => handle_detect_waste(&state).await,
                        "osint_smart_read" => handle_smart_read(&state, call.arguments).await,
                        "osint_checkpoint_save" => handle_checkpoint_save(&state, call.arguments).await,
                        _ => json!({"error": {"code": -32601, "message": "Tool not found"}})
                    },
                    Err(_) => json!({"error": {"code": -32602, "message": "Invalid params"}})
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

const OUTPUT_CAP_CHARS: usize = 2000;

/// Wraps a CallToolResult text through to_ascii_safe for safe SSE/JSON transport.
/// Prevents stream corruption from Wenyan CJK output, emojis, or non-ASCII tool output.
fn safe_result(text: String, is_error: bool) -> serde_json::Value {
    json!(CallToolResult {
        content: vec![McpContent::Text { text: to_ascii_safe(&text) }],
        is_error,
    })
}

fn cap_content(content: &str) -> (String, u64) {
    let char_count = content.chars().count();
    if char_count > OUTPUT_CAP_CHARS {
        // Corte en frontera de char — nunca en medio de un codepoint UTF-8
        let safe_end = content.char_indices()
            .nth(OUTPUT_CAP_CHARS)
            .map(|(i, _)| i)
            .unwrap_or(content.len());
        let truncated = format!(
            "{}\n... [{} chars truncados — usa osint_compress_memory_file para reducir]",
            &content[..safe_end],
            char_count - OUTPUT_CAP_CHARS
        );
        let saved = (content.len().saturating_sub(safe_end) / 4) as u64;
        (truncated, saved)
    } else {
        (content.to_string(), 0)
    }
}

async fn log_tool_call(state: &Arc<McpServer>, tool: &str, input: &str) -> Option<String> {
    let mut history = state.call_history.lock().await;
    let summary = if input.len() > 64 {
        format!("{}…{}", &input[..32], &input[input.len()-32..])
    } else {
        input.to_string()
    };
    let key = format!("{}:{}", tool, summary);
    let loop_count = history.iter().filter(|(_, k)| k == &key).count();
    if history.len() >= 20 { history.remove(0); }
    history.push((tool.to_string(), key));
    if loop_count >= 2 {
        Some(format!("⚠️ [LOOP-DETECT] '{}' llamado {}x con el mismo input. Posible alucinación en cadena.", tool, loop_count + 1))
    } else {
        None
    }
}

async fn handle_route_task(args: serde_json::Value) -> serde_json::Value {
    let task = args["task"].as_str().unwrap_or("").to_lowercase();
    let context_tokens = args["context_tokens"].as_u64().unwrap_or(0);
    let files: Vec<String> = args["files"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_lowercase()).collect())
        .unwrap_or_default();

    // Thresholds calibrated for offensive core: larger context windows expected.
    // Antigravity (Gemini): massive context / global repo reasoning
    let (model, reason, fallback) = if context_tokens > 80_000
        || task.contains("global") || task.contains("repo") || task.contains("snapshot")
        || files.len() > 15
    {
        (
            "Antigravity (Gemini 1.5 Pro)",
            format!("Massive context ({} tokens) or global reasoning task.", context_tokens),
            "Kimi (128k)",
        )
    // Claude: security/architecture precision tasks within manageable context
    } else if context_tokens < 30_000 && (
        task.contains("security") || task.contains("audit") || task.contains("exploit")
        || task.contains("architecture") || task.contains("refactor") || task.contains("sovereign")
        || files.iter().any(|f| ["poc", "proxy", "sandbox", "stealth", "engine", "plugin_loader"]
            .iter().any(|kw| f.contains(kw)))
    ) {
        (
            "Claude Code (claude-3-5-sonnet)",
            "Security/architecture precision task within Claude context budget.".to_string(),
            "Antigravity",
        )
    // Kimi: standard bulk tasks, cost-optimized
    } else {
        let reason = if context_tokens > 30_000 {
            format!("Cost-optimized for medium context ({} tokens).", context_tokens)
        } else {
            "Standard technical task. Cost efficiency prioritized.".to_string()
        };
        ("Kimi (Moonshot-v1-128k)", reason, "Claude Code")
    };

    safe_result(
        format!("[ROUTE] model:{} | reason:{} | fallback:{}", model, reason, fallback),
        false,
    )
}

async fn handle_smart_read(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let path_str = args["path"].as_str().unwrap_or("");

    // 1. Validacion de Path (Sprint 2)
    let path = match validate_path(path_str) {
        Ok(p) => p,
        Err(e) => return safe_result(e, true),
    };

    if state.sanitizer.filter_tool_output("SmartRead", path_str).is_empty()
        || path_str.contains(".env") || path_str.contains("id_rsa") || path_str.contains(".key")
    {
        return safe_result("SECURITY BLOCK: Ruta sensible bloqueada.".to_string(), true);
    }

    let content = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(e) => return safe_result(format!("Error leyendo archivo: {}", e), true),
    };

    // SHA-256 del contenido actual
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let current_hash: String = hasher.finalize().encode_hex();

    if let Some(prev_hash) = state.file_hash_cache.get(path_str) {
        if *prev_hash == current_hash {
            let saved = (content.len() / 4) as u64;
            state.tokens_saved.fetch_add(saved, Ordering::Relaxed);
            return safe_result(
                format!("[SMART-READ: NO-CHANGE] '{}' — ~{} tokens ahorrados.", path_str, saved),
                false,
            );
        }
        state.file_hash_cache.insert(path_str.to_string(), current_hash);
        let (capped, saved) = cap_content(&content);
        state.tokens_saved.fetch_add(saved, Ordering::Relaxed);
        return safe_result(format!("[SMART-READ: CHANGED] '{}'\n{}", path_str, capped), false);
    }

    state.file_hash_cache.insert(path_str.to_string(), current_hash);
    let (capped, saved) = cap_content(&content);
    state.tokens_saved.fetch_add(saved, Ordering::Relaxed);
    safe_result(format!("[SMART-READ: FIRST-READ] '{}'\n{}", path_str, capped), false)
}

async fn handle_detect_waste(state: &Arc<McpServer>) -> serde_json::Value {
    let calls = state.total_calls.load(Ordering::SeqCst);
    let tokens = state.tokens_saved.load(Ordering::SeqCst);
    let bytes = state.bytes_processed.load(Ordering::SeqCst);

    let history = state.call_history.lock().await;
    let mut loop_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (tool, _) in history.iter() {
        *loop_counts.entry(tool.as_str()).or_insert(0) += 1;
    }
    let loop_penalty = loop_counts.values().filter(|&&c| c >= 3).count() as f32 * 2.0;
    drop(history);

    let tokens_sent = bytes / 4;
    let total_potential = tokens + tokens_sent;
    let efficiency_ratio = if total_potential > 0 { tokens as f32 / total_potential as f32 } else { 0.0 };
    let efficiency_score = efficiency_ratio * 5.0;
    let bloat_penalty = if calls > 10 && efficiency_ratio < 0.1 { 2.0 } else { 0.0 };
    let mut score = 10.0 - loop_penalty + efficiency_score - bloat_penalty;
    score = score.clamp(1.0, 10.0);
    let status = if score >= 8.0 { "Sovereign (Optimo)" } else if score >= 5.0 { "Degradado" } else { "Critico" };

    safe_result(format!(
        "[OSINT-WASTE] Quality Score: {:.1}/10 [{}]\n\
        - Penalizacion Loops: -{:.1}\n\
        - Bonus Eficiencia: +{:.1}\n\
        - Penalizacion Bloat: -{:.1}\n\
        - Recomendacion: {}",
        score, status, loop_penalty, efficiency_score, bloat_penalty,
        if score < 5.0 { "Ejecutar osint_compress_memory_file inmediatamente." } else { "Sesion saludable." }
    ), false)
}

async fn handle_checkpoint_save(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let trigger = args["trigger"].as_str().unwrap_or("unknown");
    let content = args["content"].as_str().unwrap_or("");

    if content.is_empty() {
        return safe_result("Error: Contenido vacio.".to_string(), true);
    }

    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest: String = hasher.finalize().encode_hex();

    if let Some(prev) = state.checkpoint_manifest.get(trigger) {
        if prev["digest"].as_str() == Some(&digest) {
            return safe_result(
                format!("[CHECKPOINT: SKIP] Snapshot identico ya existe para '{}'.", trigger),
                false,
            );
        }
    }

    let entry = json!({
        "trigger": trigger,
        "digest": digest,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "size": content.len()
    });
    state.checkpoint_manifest.insert(trigger.to_string(), entry.clone());

    if let Some(ref db) = state.db {
        let _ = db.save_checkpoint(trigger, &entry.to_string(), content).await;
    }

    safe_result(
        format!("[CHECKPOINT: SAVED] Trigger: '{}' | Digest: {}...", trigger, &digest[..8]),
        false,
    )
}

async fn handle_execute_plugin(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let target_masked = args["target"].as_str().unwrap_or("");
    let plugin_name = args["plugin_name"].as_str().unwrap_or("");

    // Loop detection — detecta alucinaciones en cadena antes de ejecutar
    let loop_input = format!("{}:{}", plugin_name, target_masked);
    if let Some(warning) = log_tool_call(state, "osint_execute_plugin", &loop_input).await {
        warn!("{}", warning);
        // No abortamos — advertimos pero ejecutamos para no romper flujos legítimos
    }

    // 1. DESENMASCARAR (IA -> Real)
    let target_real = state.sanitizer.unmask_input(target_masked);
    info!("🛡️ [MCP-OPSEC] Interpolando '{}' -> Real: '{}'", target_masked, target_real);

    // 1.1 DERIVACIÓN DE CLAVE HARDENED (Fase 2 Hardened)
    // Combinamos: plugin + target + flags críticas de config
    let mut hasher = Sha256::new();
    hasher.update(plugin_name.as_bytes());
    hasher.update(target_real.as_bytes());
    
    // Añadimos sal de configuración para invalidación automática
    let config_salt = json!({
        "insecure": state.config.insecure,
        "nmap": state.config.nmap_options,
    }).to_string();
    hasher.update(config_salt.as_bytes());
    
    let secure_key: String = hasher.finalize().encode_hex();
    let legacy_key = format!("{}:{}", plugin_name, target_real);
    
    // Nivel 1: Moka (RAM) - Búsqueda Dual
    if let Some(cached) = state.plugin_cache.get(&secure_key) {
        state.cache_hits.fetch_add(1, Ordering::Relaxed);
        info!("🚀 [MCP-CACHE] Hit SEGURO en RAM para: {} (SHA256)", plugin_name);
        return json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("[CACHED: RAM] {}", cached) }],
            is_error: false
        });
    }
    
    // Retrocompatibilidad (F2): Si no hay hit seguro, buscar clave legacy
    if let Some(cached) = state.plugin_cache.get(&legacy_key) {
        state.cache_hits.fetch_add(1, Ordering::Relaxed);
        warn!("⚠️ [MCP-CACHE] Hit LEGACY en RAM para: {} (Migrando...)", plugin_name);
        // Migramos a la nueva clave para futuras llamadas
        state.plugin_cache.insert(secure_key.clone(), cached.clone()).await;
        return json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("[CACHED: LEGACY_RAM] {}", cached) }],
            is_error: false
        });
    }

    // Nivel 2: SQLite (Disco) - Búsqueda Dual
    if let Some(ref db) = state.db {
        // Primero intentar búsqueda segura
        if let Ok(Some(cached)) = db.load_plugin_cache(&secure_key).await {
            state.cache_hits.fetch_add(1, Ordering::Relaxed);
            info!("💾 [MCP-CACHE] Hit SEGURO en Disco para: {}", plugin_name);
            state.plugin_cache.insert(secure_key.clone(), cached.clone()).await;
            return json!(CallToolResult {
                content: vec![McpContent::Text { text: format!("[CACHED: DISK] {}", cached) }],
                is_error: false
            });
        }
        
        // Retrocompatibilidad en Disco
        if let Ok(Some(cached)) = db.load_plugin_cache(&legacy_key).await {
            state.cache_hits.fetch_add(1, Ordering::Relaxed);
            warn!("⚠️ [MCP-CACHE] Hit LEGACY en Disco para: {}. Migrando...", plugin_name);
            state.plugin_cache.insert(secure_key.clone(), cached.clone()).await;
            let _ = db.save_plugin_cache(&secure_key, &cached).await;
            return json!(CallToolResult {
                content: vec![McpContent::Text { text: format!("[CACHED: LEGACY_DISK] {}", cached) }],
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
            file_path: None,
            user: None, // Auto-detect later or assume net
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
            version: 0,
            skip_heavy_scan: false,
            scan_id: None,
            scope_id: String::new(),
        };

        // 2.1 MOTOR DE RESILIENCIA (Fase 6 Roadmap)
        let mut attempts = 0;
        let max_retries = 3;
        let mut scan_result = Err(anyhow::anyhow!("No se ha iniciado la ejecución"));

        while attempts < max_retries {
            scan_result = p.scan(&host).await;
            if scan_result.is_ok() { break; }
            
            attempts += 1;
            if attempts < max_retries {
                let delay = match attempts {
                    1 => 2,   // Backoff Conservador
                    2 => 5,
                    _ => 10,
                };
                warn!("⚠️ [MCP-RESILIENCIA] Intento {} fallido para {}. Reintentando en {}s...", attempts, plugin_name, delay);
                tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
            }
        }

        match scan_result {
            Ok(findings) => {
                // 2.2 PHASE 4: SEVERITY CAPS & TRUST PREFIXES
                use crate::models::Severity;
                let mut criticals = Vec::new();
                let mut highs = Vec::new();
                let mut mediums = Vec::new();
                let mut lows = Vec::new();

                for f in findings.iter() {
                    let mut f_filtered = f.clone();
                    
                    // Prefix Trust (F4.2)
                    let verified = f.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);
                    let prefix = if verified { "[VERIFIED]" } else { "[POTENTIAL]" };
                    f_filtered.core.description = format!("{} {}", prefix, f.core.description);
                    f_filtered.core.title = format!("{} {}", prefix, f.core.title);

                    // Semantic Filter (F1.1)
                    f_filtered.core.description = state.sanitizer.filter_tool_output(plugin_name, &f_filtered.core.description);
                    
                    if let Some(ref mut evidence) = f_filtered.evidence.primary {
                        if let Some(obj) = evidence.data.as_object_mut() {
                            if let Some(body) = obj.get_mut("body") {
                                if let Some(s) = body.as_str() {
                                    let filtered_body = state.sanitizer.filter_tool_output(plugin_name, s);
                                    *body = serde_json::json!(filtered_body);
                                }
                            }
                        }
                    }

                    match f.core.severity {
                        Severity::Critical if criticals.len() < 20 => criticals.push(f_filtered),
                        Severity::High if highs.len() < 30 => highs.push(f_filtered),
                        Severity::Medium if mediums.len() < 20 => mediums.push(f_filtered),
                        Severity::Low | Severity::Info if lows.len() < 10 => lows.push(f_filtered),
                        _ => {} // Omit by cap
                    }
                }

                let mut final_findings = Vec::new();
                final_findings.extend(criticals);
                final_findings.extend(highs);
                final_findings.extend(mediums);
                final_findings.extend(lows);

                let compressed_findings: Vec<_> = final_findings.iter()
                    .map(|f| ContextCompressor::compress_finding(f, RouteLevel::Local))
                    .collect();

                // 3. COMPRESIÓN DE CONTEXTO (Integración V14.1)
                let support_tone = args["support_tone"].as_bool().unwrap_or(false);
                let support_wenyan = args["support_wenyan"].as_bool().unwrap_or(false);
                let support_tonl = args["support_tonl"].as_bool().unwrap_or(false);
                
                let summary = if compressed_findings.is_empty() {
                    "No se encontraron hallazgos relevantes.".to_string()
                } else if support_tonl {
                    // FASE 8: TONL V1.1 — diccionario dinámico + bidireccional (MCP-OSINTULT port)
                    let arr = serde_json::Value::Array(compressed_findings.clone());
                    tonl_encode(arr)
                } else if support_tone || compressed_findings.len() > 10 {
                    // FASE 3: TONE V1 (compatibilidad legacy)
                    tone_encode(&compressed_findings)
                } else {
                    serde_json::to_string_pretty(&compressed_findings).unwrap_or_default()
                };

                // 3.2 PROMPT OPTIMIZER (MCP-OSINTULT port) — reduce prose/fillers en summaries textuales
                let summary = if !support_tone && !support_tonl && !support_wenyan {
                    let optimized = PROMPT_OPTIMIZER.optimize(&summary, crate::core::ai::token_optimizer::OptimizationLevel::Full);
                    let saved_by_opt = PromptOptimizer::savings_tokens(&summary, &optimized);
                    if saved_by_opt > 0 {
                        state.tokens_saved.fetch_add(saved_by_opt, Ordering::Relaxed);
                        info!("🔤 [MCP-OPT] PromptOptimizer: ~{} tokens adicionales ahorrados", saved_by_opt);
                    }
                    optimized
                } else {
                    summary
                };

                // 3.1 PROTOCOLO WENYAN (IA-IA)
                let content = if support_wenyan {
                    let wenyan_text = crate::core::ai::caveman::CavemanOptimizer::optimize_prompt(
                        &summary, 
                        crate::core::ai::CavemanLevel::WenyanUltra
                    );
                    McpContent::Wenyan { text: wenyan_text }
                } else {
                    McpContent::Text { text: state.sanitizer.mask_output(&summary) }
                };

                // 4. MASCARAR SALIDA (Real -> IA) - Solo si no es Wenyan (IA-IA suele usar targets enmascarados ya)
                let final_text = match &content {
                    McpContent::Text { text } => text.clone(),
                    McpContent::Wenyan { text } => text.clone(),
                };

                // 5.1 GUARDAR EN CACHÉ (Fase 2 Roadmap - Hardened)
                state.plugin_cache.insert(secure_key.clone(), final_text.clone()).await;
                if let Some(ref db) = state.db {
                    let _ = db.save_plugin_cache(&secure_key, &final_text).await;
                }

                let final_len = final_text.len();
                
                // TRACKING DE MÉTRICAS (Fase 5 Hardened)
                state.total_calls.fetch_add(1, Ordering::Relaxed);
                state.bytes_processed.fetch_add(final_len as u64, Ordering::Relaxed);
                
                // Ahorro estimado: (Hallazgos Crudos * 250 chars) - Texto Final
                let raw_est = (findings.len() as u64) * 250;
                let savings = raw_est.saturating_sub(final_len as u64);
                let token_savings = savings / 4; // Estimación cruda 4 chars/token
                state.tokens_saved.fetch_add(token_savings, Ordering::Relaxed);
                
                info!("📊 [MCP-STATS] Plugin: {} | Items: {} | Out: {} chars | Saved Tokens: ~{}", 
                    plugin_name, findings.len(), final_len, token_savings);

                // PERSISTENCIA PERIÓDICA (Sincronización a DB)
                if let Some(ref db) = state.db {
                    let mut stats_map = std::collections::HashMap::new();
                    stats_map.insert("total_calls".to_string(), 1); // Incremento delta
                    stats_map.insert("tokens_saved".to_string(), token_savings as i64);
                    stats_map.insert("bytes_processed".to_string(), final_len as i64);
                    let _ = db.update_mcp_stats(stats_map).await;
                }

                // Apply to_ascii_safe to the final content before returning
                // (critical for Wenyan output which contains CJK characters)
                let safe_content = match &content {
                    McpContent::Text { text } => McpContent::Text { text: to_ascii_safe(text) },
                    McpContent::Wenyan { text } => McpContent::Wenyan { text: to_ascii_safe(text) },
                };
                json!(CallToolResult {
                    content: vec![safe_content],
                    is_error: false
                })
            }
            Err(e) => {
                state.total_calls.fetch_add(1, Ordering::Relaxed);
                error!("❌ [MCP-RESILIENCIA] Plugin {} falló definitivamente tras {} intentos: {}", plugin_name, max_retries, e);

                if let Some(stale_data) = state.plugin_cache.get(&secure_key)
                    .or_else(|| state.plugin_cache.get(&legacy_key))
                {
                    warn!("🔄 [MCP-RESILIENCIA] Activando degradación controlada para {}. Usando caché estancada.", plugin_name);
                    return safe_result(
                        format!("[MODO_RESILIENCIA: DATOS_HISTORICOS]\nUltimo estado conocido:\n\n{}", stale_data),
                        false,
                    );
                }
                safe_result(format!("Error critico de ejecucion (Sin cache disponible): {}", e), true)
            }
        }
    } else {
        state.total_calls.fetch_add(1, Ordering::Relaxed);
        safe_result(format!("Plugin '{}' no encontrado.", plugin_name), true)
    }
}

async fn handle_get_stats(state: &Arc<McpServer>) -> serde_json::Value {
    let calls = state.total_calls.load(Ordering::SeqCst);
    let hits = state.cache_hits.load(Ordering::SeqCst);
    let tokens = state.tokens_saved.load(Ordering::SeqCst);
    let bytes = state.bytes_processed.load(Ordering::SeqCst);

    let usd_saved = (tokens as f64) * 0.000015;
    let hit_rate = if calls > 0 { (hits as f64 / calls as f64) * 100.0 } else { 0.0 };
    let tokens_sent = bytes / 4;
    let compression_ratio = if tokens + tokens_sent > 0 {
        (tokens as f64 / (tokens + tokens_sent) as f64) * 100.0
    } else { 0.0 };

    let history = state.call_history.lock().await;
    let mut loop_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (tool, _) in history.iter() {
        *loop_counts.entry(tool.as_str()).or_insert(0) += 1;
    }
    let loop_warnings: Vec<String> = loop_counts.into_iter()
        .filter(|(_, count)| *count >= 3)
        .map(|(tool, count)| format!("  [WARN] '{}': {}x en ventana", tool, count))
        .collect();
    drop(history);

    let loop_section = if loop_warnings.is_empty() {
        "  [OK] Sin loops detectados".to_string()
    } else {
        loop_warnings.join("\n")
    };

    // V14.6: WAF AI engine metrics
    let (lsh_hits, ai_inferences, waf_rate) = match &state.off_path_engine {
        Some(e) => {
            let h = e.lsh_cache_hits.load(Ordering::SeqCst);
            let i = e.ai_inference_count.load(Ordering::SeqCst);
            let rate = if h + i > 0 {
                format!("{:.1}%", h as f64 / (h + i) as f64 * 100.0)
            } else { "N/A (cold)".to_string() };
            (h, i, rate)
        }
        None => (0, 0, "N/A (disabled)".to_string()),
    };

    safe_result(format!(
        "[MCP-STATS] Rendimiento de Sesion:\n\
        - Llamadas totales: {}\n\
        - Cache Hits: {} ({:.1}%)\n\
        - Tokens Ahorrados: ~{} (ROI Est: ${:.4})\n\
        - Ratio de Compresion: {:.1}%\n\
        - Bytes Procesados: {} KB\n\
        - Archivos en Delta Cache: {}\n\
        - Loop Detection:\n{}\n\
        - WAF LSH Hits: {} | AI Inferences: {} | LSH Hit Rate: {}",
        calls, hits, hit_rate, tokens, usd_saved, compression_ratio,
        bytes / 1024, state.file_hash_cache.len(), loop_section,
        lsh_hits, ai_inferences, waf_rate
    ), false)
}

async fn handle_compress_memory(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let path_str = args["path"].as_str().unwrap_or("");
    let level_str = args["level"].as_str().unwrap_or("full");

    let level = match level_str {
        "lite"  => crate::core::ai::token_optimizer::OptimizationLevel::Lite,
        "ultra" => crate::core::ai::token_optimizer::OptimizationLevel::Ultra,
        _       => crate::core::ai::token_optimizer::OptimizationLevel::Full,
    };

    // 1. Validacion de Path (Sprint 2)
    let path = match validate_path(path_str) {
        Ok(p) => p,
        Err(e) => return safe_result(e, true),
    };

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            if state.sanitizer.filter_tool_output("MemoryCompressor", &content)
                .contains("[ERROR: FILTRADO_DE_SEGURIDAD_FALLIDO]")
            {
                return safe_result(
                    "Error: El archivo contiene secretos criticos sin enmascarar. Abortando por OPSEC.".to_string(),
                    true,
                );
            }

            let optimized = PROMPT_OPTIMIZER.optimize(&content, level);
            let saved_tokens = PromptOptimizer::savings_tokens(&content, &optimized);

            let backup_path = path.with_extension("original.md");
            if !backup_path.exists() {
                let _ = tokio::fs::write(&backup_path, &content).await;
            }

            match tokio::fs::write(&path, &optimized).await {
                Ok(_) => {
                    state.tokens_saved.fetch_add(saved_tokens, Ordering::Relaxed);
                    safe_result(format!(
                        "[GAP-4] Compresion completada para '{}':\n\
                        - Nivel: {:?}\n\
                        - Tokens ahorrados: ~{}\n\
                        - Backup: '{}'",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or(path_str),
                        level, saved_tokens, backup_path.display()
                    ), false)
                }
                Err(_) => safe_result("Error: No se pudo escribir el archivo optimizado.".to_string(), true),
            }
        }
        Err(e) => safe_result(format!("Error al leer el archivo: {}", e), true),
    }
}
