use axum::{
    extract::{Path, State},
    response::{IntoResponse, sse::{Event, Sse}},
    Json,
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use serde_json::json;

use crate::core::mcp::protocol::JsonRpcRequest;
use super::{McpServer, ValidatedOperator};

pub async fn sse_handler(
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

pub async fn message_handler(
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
                match serde_json::from_value::<crate::core::mcp::protocol::CallToolRequest>(params) {
                    Ok(call) => match call.name.as_str() {
                        "osint_route_task" => super::tools::handle_route_task(call.arguments).await,
                        "osint_execute_plugin" => super::execute::handle_execute_plugin(&state, call.arguments).await,
                        "osint_compress_memory_file" => super::tools::handle_compress_memory(&state, call.arguments).await,
                        "mcp_get_stats" => super::tools::handle_get_stats(&state).await,
                        "osint_detect_waste" => super::tools::handle_detect_waste(&state).await,
                        "osint_smart_read" => super::tools::handle_smart_read(&state, call.arguments).await,
                        "osint_checkpoint_save" => super::tools::handle_checkpoint_save(&state, call.arguments).await,
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
