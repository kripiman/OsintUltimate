use axum::{
    extract::{State, Path},
    response::{sse::{Event, Sse}, IntoResponse},
    routing::{get, post},
    Json, Router,
};
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

use crate::core::sink::SqliteSink;
use crate::utils::tone::tone_encode;
use std::path::PathBuf;
use moka::future::Cache;

pub struct McpServer {
    config: Arc<GlobalConfig>,
    sanitizer: Arc<DataSanitizer>,
    sessions: Arc<dashmap::DashMap<String, mpsc::Sender<Event>>>,
    db: Option<Arc<SqliteSink>>,
    plugin_cache: Cache<String, String>,
    
    // PHASE 5: Métricas de Sesión Optimidadas (Atomics)
    pub total_calls: AtomicU32,
    pub cache_hits: AtomicU32,
    pub tokens_saved: AtomicU64,
    pub bytes_processed: AtomicU64,
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
            total_calls: AtomicU32::new(0),
            cache_hits: AtomicU32::new(0),
            tokens_saved: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
        }
    }

    pub async fn with_sqlite(mut self, path: PathBuf) -> Self {
        if let Ok(db) = SqliteSink::new(path).await {
            // Cargar métricas históricas de la base de datos
            if let Ok(stats) = db.get_mcp_stats().await {
                if let Some(v) = stats.get("total_calls") { self.total_calls.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("cache_hits") { self.cache_hits.store(*v as u32, Ordering::SeqCst); }
                if let Some(v) = stats.get("tokens_saved") { self.tokens_saved.store(*v as u64, Ordering::SeqCst); }
                if let Some(v) = stats.get("bytes_processed") { self.bytes_processed.store(*v as u64, Ordering::SeqCst); }
            }
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
                                },
                                "support_tone": {
                                    "type": "boolean",
                                    "description": "Indica si el cliente soporta el formato denso TONE. Recomendado para ahorrar tokens."
                                }
                            },
                            "required": ["target", "plugin_name"]
                        }
                    },
                    {
                        "name": "mcp_get_stats",
                        "description": "Retorna estadísticas de eficiencia del MCP (ahorro de tokens, tasa de caché, etc.). Úsalo para informar al usuario sobre el rendimiento del sistema.",
                        "inputSchema": { "type": "object", "properties": {} }
                    }
                ]
            })
        },
        "tools/call" => {
            if let Some(params) = payload.params {
                let call: CallToolRequest = serde_json::from_value(params).unwrap();
                match call.name.as_str() {
                    "osint_execute_plugin" => handle_execute_plugin(&state, call.arguments).await,
                    "mcp_get_stats" => handle_get_stats(&state).await,
                    _ => json!({"error": {"code": -32601, "message": "Tool not found"}})
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
            user: None, // Auto-detect later or assume net
            findings: Arc::new(Vec::new()),
            tool_suggestions: Arc::new(Vec::new()),
            tactical_context: Arc::new(json!({})),
            extra_data: Arc::new(json!({})),
        };

        match p.scan(&host).await {
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
                    let prefix = if f.evidence.verified { "[VERIFIED]" } else { "[POTENTIAL]" };
                    f_filtered.description = format!("{} {}", prefix, f.description);
                    f_filtered.title = format!("{} {}", prefix, f.title);

                    // Semantic Filter (F1.1)
                    f_filtered.description = state.sanitizer.filter_tool_output(plugin_name, &f_filtered.description);
                    
                    if let Some(obj) = f_filtered.evidence.data.as_object_mut() {
                        if let Some(body) = obj.get_mut("body") {
                            if let Some(s) = body.as_str() {
                                let filtered_body = state.sanitizer.filter_tool_output(plugin_name, s);
                                *body = serde_json::json!(filtered_body);
                            }
                        }
                    }

                    match f.severity {
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
                
                let summary = if compressed_findings.is_empty() {
                    "No se encontraron hallazgos relevantes.".to_string()
                } else if support_tone || compressed_findings.len() > 10 {
                    // FASE 3: Serialización TONE para densidad de datos (Completado con Negociación)
                    tone_encode(&compressed_findings)
                } else {
                    serde_json::to_string_pretty(&compressed_findings).unwrap_or_default()
                };

                // 4. MASCARAR SALIDA (Real -> IA)
                // Nota: El filtrado semántico ya se aplicó individualmente arriba
                let final_text = state.sanitizer.mask_output(&summary);

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
                let savings = if raw_est > final_len as u64 { raw_est - final_len as u64 } else { 0 };
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
                    if let Ok(Some(_)) = db.load_plugin_cache(&secure_key).await {
                        // Si ya estaba en la DB pero no en RAM, esto se manejaría arriba, 
                        // pero aquí solo sumamos a los globales si no es un hit puro.
                    }
                    let _ = db.update_mcp_stats(stats_map).await;
                }

                json!(CallToolResult {
                    content: vec![McpContent::Text { text: final_text }],
                    is_error: false
                })
            }
            Err(e) => {
                state.total_calls.fetch_add(1, Ordering::Relaxed);
                error!("Error ejecutando plugin {} en MCP: {}", plugin_name, e);
                json!(CallToolResult {
                    content: vec![McpContent::Text { text: format!("Error de ejecución: {}", e) }],
                    is_error: true
                })
            }
        }
    } else {
        state.total_calls.fetch_add(1, Ordering::Relaxed);
        json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("Plugin '{}' no encontrado.", plugin_name) }],
            is_error: true
        })
    }
}

async fn handle_get_stats(state: &Arc<McpServer>) -> serde_json::Value {
    let calls = state.total_calls.load(Ordering::SeqCst);
    let hits = state.cache_hits.load(Ordering::SeqCst);
    let tokens = state.tokens_saved.load(Ordering::SeqCst);
    let bytes = state.bytes_processed.load(Ordering::SeqCst);
    
    let hit_rate = if calls > 0 { (hits as f64 / calls as f64) * 100.0 } else { 0.0 };
    
    let stats_text = format!(
        "📊 **Informe de Eficiencia MCP OsintUltimate**\n\n\
        - **Total de Consultas:** {}\n\
        - **Aciertos de Caché:** {} ({:.2}% de eficiencia operativa)\n\
        - **Tokens Ahorrados:** ~{} (Aprox. ${:.2} USD ahorrados)\n\
        - **Datos Saneados:** {} bytes\n\n\
        *Nota: El ahorro se calcula comparando el formato crudo JSON vs TONE V1.*",
        calls, hits, hit_rate, tokens, (tokens as f64 * 0.000015), bytes // Estimación coste GPT-4o-like
    );

    json!(CallToolResult {
        content: vec![McpContent::Text { text: stats_text }],
        is_error: false
    })
}
