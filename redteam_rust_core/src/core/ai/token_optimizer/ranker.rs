/// token_optimizer/ranker.rs — ContextRanker implementation.
use std::collections::HashSet;
use regex::Regex;
use once_cell::sync::Lazy;
use moka::sync::Cache;

pub struct ContextRanker {
    cache: Cache<String, Vec<(String, f64)>>,
}

impl Default for ContextRanker {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextRanker {
    pub fn new() -> Self {
        Self { 
            cache: Cache::builder()
                .max_capacity(50)
                .time_to_idle(std::time::Duration::from_secs(3600))
                .build() 
        }
    }

    fn score_files(&self, query_terms: &[String], files: &[(String, String)]) -> Vec<(String, String, f64)> {
        let mut initial_scores: Vec<(String, String, f64)> = files.iter()
            .map(|(path, content)| {
                let mut score = 0.0;
                let pl = path.to_lowercase();
                let cl = content.to_lowercase();
                for term in query_terms {
                    if pl.contains(term.as_str()) { score += 10.0; }
                    score += cl.matches(term.as_str()).count() as f64 * 0.5;
                }
                if path.ends_with(".rs") { score += 2.0; }
                if path.ends_with(".md") { score += 1.0; }
                if let Ok(meta) = std::fs::metadata(path) {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(elapsed) = modified.elapsed() {
                            let days = elapsed.as_secs() / 86400;
                            if days < 7 { score += 5.0 - (days as f64 * 0.5); }
                        }
                    }
                }
                (path.clone(), content.clone(), score)
            })
            .collect();

        initial_scores.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        initial_scores
    }

    fn mmr_select(
        &self,
        mut initial_scores: Vec<(String, String, f64)>,
        max_tokens: u64,
        lambda: f64,
    ) -> Vec<(String, String, f64)> {
        let mut selected: Vec<(String, String, f64)> = Vec::new();
        let mut current_tokens = 0u64;

        while !initial_scores.is_empty() && selected.len() < 30 {
            let best_idx = initial_scores.iter().enumerate()
                .map(|(i, (_, content, score))| {
                    let redundancy = if selected.is_empty() { 0.0 } else {
                        selected.iter()
                            .map(|(_, sc, _)| Self::jaccard(content, sc))
                            .fold(0.0f64, f64::max)
                    };
                    (i, lambda * score - (1.0 - lambda) * redundancy * 15.0)
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(0);

            let (p, c, s) = initial_scores.remove(best_idx);
            let file_tokens = (c.len() / 4) as u64;
            if current_tokens + file_tokens > max_tokens && !selected.is_empty() { break; }

            let deps = Self::extract_deps(&c);
            for (rp, _rc, rs) in initial_scores.iter_mut() {
                let stem = std::path::Path::new(rp)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                if deps.contains(&stem.to_string()) {
                    *rs += 7.0;
                }
            }

            current_tokens += file_tokens;
            selected.push((p, c, s));
        }
        selected
    }

    pub fn rank_files(
        &self,
        query: &str,
        files: &[(String, String)],
        token_budget: Option<u64>,
        lambda: Option<f64>,
    ) -> Vec<(String, f64)> {
        let lambda = lambda.unwrap_or(0.65);
        let cache_key = format!("{}:{}:{:?}:{:.2}", query, files.len(), token_budget, lambda);

        if let Some(hits) = self.cache.get(&cache_key) {
            return hits.clone();
        }

        let query_terms: Vec<String> = query.to_lowercase()
            .split_whitespace().map(|s| s.to_string()).collect();

        let initial_scores = self.score_files(&query_terms, files);
        let max_tokens = token_budget.unwrap_or(32_000);
        let selected = self.mmr_select(initial_scores, max_tokens, lambda);

        let result: Vec<(String, f64)> = selected.into_iter().map(|(p, _, s)| (p, s)).collect();
        self.cache.insert(cache_key, result.clone());
        result
    }

    fn jaccard(a: &str, b: &str) -> f64 {
        static STOP: Lazy<HashSet<&'static str>> = Lazy::new(|| {
            ["the","a","an","and","or","to","for","with","in","on","is","are","was","were","it","this","that"]
                .iter().cloned().collect()
        });
        let tokens = |s: &str| -> HashSet<String> {
            s.split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase())
                .filter(|w| !w.is_empty() && !STOP.contains(w.as_str()))
                .take(200)
                .collect()
        };
        let sa = tokens(a);
        let sb = tokens(b);
        let inter = sa.intersection(&sb).count() as f64;
        let union = sa.union(&sb).count() as f64;
        if union == 0.0 { 0.0 } else { inter / union }
    }

    fn extract_deps(content: &str) -> Vec<String> {
        static RE_USE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?m)^\s*(?:pub\s+)?(?:use|mod)\s+([^;\{]+)(?:;|\{)").unwrap()
        });
        static RE_BRACES: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{([^}]+)\}").unwrap());

        let mut deps = Vec::new();
        for cap in RE_USE.captures_iter(content) {
            let path = &cap[1];
            if let Some(last) = path.trim().split("::").last() {
                let clean = last.trim().trim_matches('"');
                if clean.len() > 1 && !matches!(clean, "self" | "super" | "crate") {
                    deps.push(clean.to_string());
                }
            }
        }
        for cap in RE_BRACES.captures_iter(content) {
            for part in cap[1].split(',') {
                let clean = part.trim().split(" as ").next().unwrap_or("").trim();
                if clean.len() > 1 && !matches!(clean, "self" | "super") {
                    deps.push(clean.to_string());
                }
            }
        }
        deps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ranker_returns_relevant_first() {
        let files = vec![
            ("src/proxy.rs".to_string(), "pub struct ProxyManager;".to_string()),
            ("docs/audit.md".to_string(), "Security audit proxy module.".to_string()),
            ("src/main.rs".to_string(), "fn main() {}".to_string()),
        ];
        let ranker = ContextRanker::new();
        let scores = ranker.rank_files("proxy security", &files, None, None);
        assert!(!scores.is_empty());
        assert!(scores[0].0.contains("proxy") || scores[0].0.contains("audit"));
    }
}
