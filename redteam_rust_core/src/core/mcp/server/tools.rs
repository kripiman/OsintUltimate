use std::sync::Arc;
use std::sync::atomic::Ordering;
use serde_json::json;
use sha2::{Sha256, Digest};
use hex::ToHex;

use crate::core::mcp::protocol::{CallToolResult, McpContent};
use crate::utils::tone::to_ascii_safe;
use crate::core::ai::token_optimizer::PromptOptimizer;
use crate::core::ai::PROMPT_OPTIMIZER;

use super::McpServer;

pub const OUTPUT_CAP_CHARS: usize = 2000;

/// Helper to sanitize and validate paths inside the workspace.
pub fn validate_path(path_str: &str) -> Result<std::path::PathBuf, String> {
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

/// Wraps a CallToolResult text through to_ascii_safe for safe SSE/JSON transport.
/// Prevents stream corruption from Wenyan CJK output, emojis, or non-ASCII tool output.
pub fn safe_result(text: String, is_error: bool) -> serde_json::Value {
    json!(CallToolResult {
        content: vec![McpContent::Text { text: to_ascii_safe(&text) }],
        is_error,
    })
}

pub fn cap_content(content: &str) -> (String, u64) {
    let char_count = content.chars().count();
    if char_count > OUTPUT_CAP_CHARS {
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

pub async fn handle_route_task(args: serde_json::Value) -> serde_json::Value {
    let task = args["task"].as_str().unwrap_or("").to_lowercase();
    let context_tokens = args["context_tokens"].as_u64().unwrap_or(0);
    let files: Vec<String> = args["files"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(|s| s.to_lowercase()).collect())
        .unwrap_or_default();

    let (model, reason, fallback) = if context_tokens > 80_000
        || task.contains("global") || task.contains("repo") || task.contains("snapshot")
        || files.len() > 15
    {
        (
            "Antigravity (Gemini 1.5 Pro)",
            format!("Massive context ({} tokens) or global reasoning task.", context_tokens),
            "Kimi (128k)",
        )
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

pub async fn handle_smart_read(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let path_str = args["path"].as_str().unwrap_or("");

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

pub async fn handle_detect_waste(state: &Arc<McpServer>) -> serde_json::Value {
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

pub async fn handle_checkpoint_save(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
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

pub async fn handle_get_stats(state: &Arc<McpServer>) -> serde_json::Value {
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

pub async fn handle_compress_memory(state: &Arc<McpServer>, args: serde_json::Value) -> serde_json::Value {
    let path_str = args["path"].as_str().unwrap_or("");
    let level_str = args["level"].as_str().unwrap_or("full");

    let level = match level_str {
        "lite"  => crate::core::ai::token_optimizer::OptimizationLevel::Lite,
        "ultra" => crate::core::ai::token_optimizer::OptimizationLevel::Ultra,
        _       => crate::core::ai::token_optimizer::OptimizationLevel::Full,
    };

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
