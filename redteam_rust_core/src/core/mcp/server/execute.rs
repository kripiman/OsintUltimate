use std::sync::Arc;
use std::sync::atomic::Ordering;
use serde_json::{json, Value};
use sha2::{Sha256, Digest};
use hex::ToHex;
use tracing::{info, error, warn};

use crate::models::{TargetHost, TargetStatus, TargetType, Severity};
use crate::core::ai::compressor::ContextCompressor;
use crate::core::ai::types::RouteLevel;
use crate::core::mcp::protocol::{CallToolResult, McpContent};
use crate::utils::tone::{tone_encode, tonl_encode, to_ascii_safe};

use super::McpServer;
use super::tools::safe_result;

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

pub async fn handle_execute_plugin(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let target_masked = args["target"].as_str().unwrap_or("");
    let plugin_name = args["plugin_name"].as_str().unwrap_or("");

    let loop_input = format!("{}:{}", plugin_name, target_masked);
    if let Some(warning) = log_tool_call(state, "osint_execute_plugin", &loop_input).await {
        warn!("{}", warning);
    }

    // 1. DESENMASCARAR (IA -> Real)
    let target_real = state.sanitizer.unmask_input(target_masked);
    info!("🛡️ [MCP-OPSEC] Interpolando '{}' -> Real: '{}'", target_masked, target_real);

    // 1.1 DERIVACIÓN DE CLAVE HARDENED (Fase 2 Hardened)
    let mut hasher = Sha256::new();
    hasher.update(plugin_name.as_bytes());
    hasher.update(target_real.as_bytes());
    
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
    
    // Retrocompatibilidad (F2)
    if let Some(cached) = state.plugin_cache.get(&legacy_key) {
        state.cache_hits.fetch_add(1, Ordering::Relaxed);
        warn!("⚠️ [MCP-CACHE] Hit LEGACY en RAM para: {} (Migrando...)", plugin_name);
        state.plugin_cache.insert(secure_key.clone(), cached.clone()).await;
        return json!(CallToolResult {
            content: vec![McpContent::Text { text: format!("[CACHED: LEGACY_RAM] {}", cached) }],
            is_error: false
        });
    }

    // Nivel 2: SQLite (Disco) - Búsqueda Dual
    if let Some(ref db) = state.db {
        if let Ok(Some(cached)) = db.load_plugin_cache(&secure_key).await {
            state.cache_hits.fetch_add(1, Ordering::Relaxed);
            info!("💾 [MCP-CACHE] Hit SEGURO en Disco para: {}", plugin_name);
            state.plugin_cache.insert(secure_key.clone(), cached.clone()).await;
            return json!(CallToolResult {
                content: vec![McpContent::Text { text: format!("[CACHED: DISK] {}", cached) }],
                is_error: false
            });
        }
        
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
        let host = TargetHost {
            host: target_real.clone(),
            ip: None,
            resolved_ip: None,
            status: TargetStatus::Scanning,
            target_type: TargetType::Network,
            file_path: None,
            user: None,
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
                        _ => {}
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
                    let arr = Value::Array(compressed_findings.clone());
                    tonl_encode(arr)
                } else if support_tone || compressed_findings.len() > 10 {
                    tone_encode(&compressed_findings)
                } else {
                    serde_json::to_string_pretty(&compressed_findings).unwrap_or_default()
                };

                // 3.2 PROMPT OPTIMIZER (MCP-OSINTULT port)
                let summary = if !support_tone && !support_tonl && !support_wenyan {
                    let optimized = crate::core::ai::PROMPT_OPTIMIZER.optimize(&summary, crate::core::ai::token_optimizer::OptimizationLevel::Full);
                    let saved_by_opt = crate::core::ai::token_optimizer::PromptOptimizer::savings_tokens(&summary, &optimized);
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

                // 4. MASCARAR SALIDA
                let final_text = match &content {
                    McpContent::Text { text } => text.clone(),
                    McpContent::Wenyan { text } => text.clone(),
                };

                // 5.1 GUARDAR EN CACHÉ
                state.plugin_cache.insert(secure_key.clone(), final_text.clone()).await;
                if let Some(ref db) = state.db {
                    let _ = db.save_plugin_cache(&secure_key, &final_text).await;
                }

                let final_len = final_text.len();
                
                // TRACKING DE MÉTRICAS
                state.total_calls.fetch_add(1, Ordering::Relaxed);
                state.bytes_processed.fetch_add(final_len as u64, Ordering::Relaxed);
                
                let raw_est = (findings.len() as u64) * 250;
                let savings = raw_est.saturating_sub(final_len as u64);
                let token_savings = savings / 4;
                state.tokens_saved.fetch_add(token_savings, Ordering::Relaxed);
                
                info!("📊 [MCP-STATS] Plugin: {} | Items: {} | Out: {} chars | Saved Tokens: ~{}", 
                    plugin_name, findings.len(), final_len, token_savings);

                // PERSISTENCIA PERIÓDICA
                if let Some(ref db) = state.db {
                    let mut stats_map = std::collections::HashMap::new();
                    stats_map.insert("total_calls".to_string(), 1);
                    stats_map.insert("tokens_saved".to_string(), token_savings as i64);
                    stats_map.insert("bytes_processed".to_string(), final_len as i64);
                    let _ = db.update_mcp_stats(stats_map).await;
                }

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
