use crate::plugins::PluginMetadata;
use crate::models::Finding;
use std::collections::HashSet;
use once_cell::sync::Lazy;

/// V15: PLUGIN RAG OPTIMIZER
/// Deterministic scoring engine for tool selection without token-heavy LLM overhead.
pub struct PluginRagManager;

impl PluginRagManager {
    /// Selects the top_k most relevant plugins for a given finding and attack context.
    pub fn select_tools(
        finding: &Finding,
        attack_context: Option<&str>,
        plugins: &[PluginMetadata],
        top_k: usize,
    ) -> Vec<PluginMetadata> {
        let query = format!("{} {} {}", 
            finding.title, 
            finding.description, 
            attack_context.unwrap_or_default()
        ).to_lowercase();
        
        let query_terms: HashSet<String> = query
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        let mut scored: Vec<(f32, PluginMetadata)> = plugins.iter().cloned().map(|p| {
            let mut score = 0.0;
            let name_low = p.name.to_lowercase();
            let desc_low = p.description.to_lowercase();
            
            // 1. Exact Name/Category Match (High Signal)
            if query.contains(&name_low) { score += 10.0; }
            if query.contains(&p.category.to_lowercase()) { score += 5.0; }
            
            // 2. Keyword Overlap (Description & MITRE)
            for term in &query_terms {
                if desc_low.contains(term) { score += 1.0; }
                if p.mitre_attacks.iter().any(|m| m.to_lowercase().contains(term)) {
                    score += 3.0;
                }
            }
            
            // 3. Capability Weighting
            // If the query mentions common exploitation terms, boost relevant capabilities
            if query.contains("sql") && p.capabilities.contains(&crate::plugins::Capability::SqlInjection) { score += 15.0; }
            if query.contains("xss") && p.capabilities.contains(&crate::plugins::Capability::XssScanning) { score += 15.0; }
            if query.contains("brute") && p.capabilities.contains(&crate::plugins::Capability::BruteForce) { score += 10.0; }
            
            // 4. Posture/Risk Alignment
            // (Future: Bias towards lower risk unless in Breach posture)

            (score, p)
        }).collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored.into_iter()
            .take(top_k)
            .map(|(_, p)| p)
            .collect()
    }
}

pub static PLUGIN_RAG: Lazy<PluginRagManager> = Lazy::new(|| PluginRagManager);
