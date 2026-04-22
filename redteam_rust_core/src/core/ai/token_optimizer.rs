/// Token optimization pipeline ported from MCP-OSINTULT.
/// Integrates PromptOptimizer (10-stage) and ContextRanker (MMR) into the core AI layer.
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use regex::Regex;
use once_cell::sync::Lazy;

// ─── Constants ───────────────────────────────────────────────────────────────

const PROTECTED_TAG_START: &str = "<KEEP>";
const PROTECTED_TAG_END: &str = "</KEEP>";

// Pre-compiled static regexes (fix for MCP-OSINTULT's VerbosityReducer hot-path bug)
static RE_ARTICLES: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(the|a|an)\b").unwrap());

static RE_SUFFIX_ING: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ing\b").unwrap());
static RE_SUFFIX_ED:  Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ed\b").unwrap());
static RE_SUFFIX_LY:  Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ly\b").unwrap());

static RE_PUNCTUATION: Lazy<Regex> = Lazy::new(|| Regex::new(r"[,;!?](?:\s|$)").unwrap());

static ENTROPY_PRUNER: Lazy<Regex> = Lazy::new(|| {
    let words = [
        "basically", "essentially", "actually", "literally", "simply",
        "really", "very", "just", "quite", "rather", "extremely",
        "totally", "completely", "highly", "largely", "mainly",
        "mostly", "certainly", "definitely", "probably", "possibly",
    ];
    Regex::new(&format!(r"(?i)\b({})\b\s?", words.join("|"))).unwrap()
});

// Wenyan lexical substitution map (static — compiled once)
static WENYAN_MAP: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?i)\baudit\b").unwrap(),          "查"),
    (Regex::new(r"(?i)\bsecurity\b").unwrap(),       "安"),
    (Regex::new(r"(?i)\bsystem\b").unwrap(),         "系"),
    (Regex::new(r"(?i)\bcode\b").unwrap(),           "碼"),
    (Regex::new(r"(?i)\blogic\b").unwrap(),          "理"),
    (Regex::new(r"(?i)\bnetwork\b").unwrap(),        "網"),
    (Regex::new(r"(?i)\bprocess\b").unwrap(),        "法"),
    (Regex::new(r"(?i)\buser\b").unwrap(),           "客"),
    (Regex::new(r"(?i)\binput\b").unwrap(),          "入"),
    (Regex::new(r"(?i)\boutput\b").unwrap(),         "出"),
    (Regex::new(r"(?i)\barchitecture\b").unwrap(),   "構"),
    (Regex::new(r"(?i)\bvulnerability\b").unwrap(),  "穴"),
    (Regex::new(r"(?i)\binfrastructure\b").unwrap(), "基"),
    (Regex::new(r"(?i)\bsnapshot\b").unwrap(),       "影"),
    (Regex::new(r"(?i)\bcontext\b").unwrap(),        "境"),
    (Regex::new(r"(?i)\boptimiz\w+\b").unwrap(),     "極"),
    (Regex::new(r"(?i)\bcritical\b").unwrap(),       "危"),
    (Regex::new(r"(?i)\bexecut\w+\b").unwrap(),      "行"),
    (Regex::new(r"(?i)\bperform\b").unwrap(),        "行"),
    (Regex::new(r"(?i)\banalysis\b").unwrap(),       "析"),
]);

static VERBOSITY_RULES: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?i)in order to").unwrap(), "to"),
    (Regex::new(r"(?i)due to the fact that").unwrap(), "because"),
    (Regex::new(r"(?i)at this point in time").unwrap(), "now"),
    (Regex::new(r"(?i)has the ability to").unwrap(), "can"),
    (Regex::new(r"(?i)it is important to").unwrap(), "must"),
    (Regex::new(r"(?i)take into account").unwrap(), "consider"),
    (Regex::new(r"(?i)a large number of").unwrap(), "many"),
    (Regex::new(r"(?i)prior to").unwrap(), "before"),
    (Regex::new(r"(?i)subsequent to").unwrap(), "after"),
    (Regex::new(r"(?i)in the event that").unwrap(), "if"),
    (Regex::new(r"(?i)in spite of the fact that").unwrap(), "although"),
    (Regex::new(r"(?i)it is possible that").unwrap(), "maybe"),
    (Regex::new(r"(?i)it is essential that").unwrap(), "must"),
    (Regex::new(r"(?i)in the near future").unwrap(), "soon"),
    (Regex::new(r"(?i)at the present time").unwrap(), "now"),
    (Regex::new(r"(?i)perform an audit").unwrap(), "audit"),
    (Regex::new(r"(?i)conduct a review").unwrap(), "review"),
]);

static FILLERS: Lazy<Regex> = Lazy::new(|| {
    let words = [
        "please", "kindly", "just", "very", "really", "basically", "actually",
        "ensure", "simply", "essentially", "highly", "extremely", "totally",
        "literally", "quite", "rather", "certainly", "definitely",
        "basically", "essentially", "actually", "literally", "simply",
        "really", "very", "just", "quite", "rather", "extremely",
        "totally", "completely", "highly", "largely", "mainly", "mostly",
    ];
    Regex::new(&format!(r"(?i)\b({})\b\s?", words.join("|"))).unwrap()
});

static SYNONYMS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("asynchronous", "async");
    m.insert("synchronous", "sync");
    m.insert("development", "dev");
    m.insert("vulnerability", "vuln");
    m.insert("authentication", "auth");
    m.insert("authorization", "auth");
    m.insert("configuration", "config");
    m.insert("infrastructure", "infra");
    m.insert("architecture", "arch");
    m.insert("documentation", "doc");
    m.insert("implementation", "impl");
    m.insert("information", "info");
    m.insert("optimization", "opt");
    m.insert("performance", "perf");
    m.insert("application", "app");
    m.insert("repository", "repo");
    m.insert("dependency", "dep");
    m.insert("dependencies", "deps");
    m
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationLevel {
    Off,
    Lite,
    Full,
    Ultra,
}

impl Default for OptimizationLevel {
    fn default() -> Self {
        OptimizationLevel::Full
    }
}

// ─── Strategy trait ───────────────────────────────────────────────────────────

trait OptimizationStrategy: Send + Sync {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String;
}

// ─── Strategies ───────────────────────────────────────────────────────────────

struct ArticleStripper;
impl OptimizationStrategy for ArticleStripper {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        RE_ARTICLES.replace_all(input, "").to_string()
    }
}

struct FillerRemover;
impl OptimizationStrategy for FillerRemover {
    fn optimize(&self, input: &str, _level: OptimizationLevel) -> String {
        FILLERS.replace_all(input, "").to_string()
    }
}

struct VerbosityReducer;
impl OptimizationStrategy for VerbosityReducer {
    fn optimize(&self, input: &str, _level: OptimizationLevel) -> String {
        // Uses pre-compiled static VERBOSITY_RULES — no hot-path regex compilation
        let mut res = input.to_string();
        for (re, rep) in VERBOSITY_RULES.iter() {
            res = re.replace_all(&res, *rep).to_string();
        }
        res
    }
}

struct SynonymMapper;
impl OptimizationStrategy for SynonymMapper {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        input.split_whitespace()
            .map(|word| {
                let lower = word.to_lowercase();
                let clean = lower.trim_matches(|c: char| !c.is_alphanumeric());
                
                // Ultra level allows more aggressive abbreviations
                let mapping = if level == OptimizationLevel::Ultra {
                    SYNONYMS.get(clean)
                } else {
                    SYNONYMS.get(clean).filter(|&&s| s.len() < clean.len())
                };

                mapping
                    .map(|&s| s.to_string())
                    .unwrap_or_else(|| word.to_string())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

struct ExtractiveCompressor;
impl ExtractiveCompressor {
    fn score_line(line: &str) -> f32 {
        static TECH_KW: &[&str] = &[
            "proxy", "egress", "token", "payload", "audit", "security", "infra",
            "ghost", "strike", "breach", "sovereign", "stealth", "vuln", "config",
            "impl", "arch", "async", "sync", "error", "critical", "warning",
        ];
        let lower = line.to_lowercase();
        let mut score: f32 = TECH_KW.iter().filter(|&&kw| lower.contains(kw)).count() as f32;
        if score == 0.0 && line.len() > 50 { score -= 0.5; }
        
        // ILP-Lite: Weighting based on position and length
        if line.starts_with('#') { score += 2.0; }
        if line.starts_with('-') { score += 1.0; }
        
        score
    }
}
impl OptimizationStrategy for ExtractiveCompressor {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        
        let lines: Vec<&str> = input.lines().collect();
        if lines.len() < 10 { return input.to_string(); }

        let ratio = match level {
            OptimizationLevel::Ultra => 0.4,
            OptimizationLevel::Full => 0.7,
            _ => 1.0,
        };

        let keep_count = (lines.len() as f32 * ratio) as usize;
        let mut scored: Vec<(usize, f32)> = lines.iter().enumerate()
            .map(|(i, &l)| (i, Self::score_line(l)))
            .collect();
            
        // Greedy line selection (Approximates ILP for sequence selection)
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let kept: HashSet<usize> = scored.iter()
            .take(keep_count)
            .map(|&(i, _)| i)
            .collect();

        lines.iter().enumerate()
            .filter(|(i, l)| kept.contains(i) || l.starts_with('#') || (level != OptimizationLevel::Ultra && l.starts_with('-')))
            .map(|(_, &l)| l)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Strips common suffixes (-ing, -ed, -ly) to reduce token surface.
/// Only applies to Full/Ultra levels — Lite preserves natural language.
struct SuffixLemmatizer;
impl OptimizationStrategy for SuffixLemmatizer {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        // Apply suffix stripping only on prose lines, not code lines
        input.lines().map(|line| {
            let is_code = line.contains("fn ") || line.contains("let ") ||
                          line.contains("pub ") || line.contains("::")||  line.contains("{");
            if is_code { return line.to_string(); }
            let s = RE_SUFFIX_ING.replace_all(line, "$1");
            let s = RE_SUFFIX_ED.replace_all(&s, "$1");
            RE_SUFFIX_LY.replace_all(&s, "$1").to_string()
        }).collect::<Vec<_>>().join("\n")
    }
}

/// Removes low-entropy adverbs that carry no technical signal.
/// Complements FillerRemover with a tighter, entropy-focused list.
struct EntropyPruner;
impl OptimizationStrategy for EntropyPruner {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        ENTROPY_PRUNER.replace_all(input, "").to_string()
    }
}

/// Strips non-essential punctuation (commas, semicolons, exclamation, question marks).
/// Preserves colons (key:value), dots (paths/versions), and hyphens (identifiers).
/// Only active at Ultra level to avoid breaking prose readability at Full.
struct PunctuationPruner;
impl OptimizationStrategy for PunctuationPruner {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level != OptimizationLevel::Ultra { return input.to_string(); }
        RE_PUNCTUATION.replace_all(input, " ").to_string()
    }
}

/// Lexical Wenyan substitution: replaces high-frequency technical English terms
/// with single CJK characters (~85% char reduction on matched terms).
/// Active only at Ultra level — preserves readability at Full/Lite.
/// Complements caveman.rs (which wraps LLM instructions) by transforming output text directly.
struct WenyanUltraStrategy;
impl OptimizationStrategy for WenyanUltraStrategy {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level != OptimizationLevel::Ultra { return input.to_string(); }
        let mut res = input.to_string();
        for (re, glyph) in WENYAN_MAP.iter() {
            res = re.replace_all(&res, *glyph).to_string();
        }
        res
    }
}

struct Deduplicator;
impl OptimizationStrategy for Deduplicator {
    fn optimize(&self, input: &str, _level: OptimizationLevel) -> String {
        let mut result = Vec::new();
        let mut last = String::new();
        for line in input.lines() {
            let t = line.trim();
            if t.is_empty() || t == last { continue; }
            result.push(t.to_string());
            last = t.to_string();
        }
        result.join("\n")
    }
}

// ─── PromptOptimizer ─────────────────────────────────────────────────────────

/// 10-stage deterministic prompt optimizer (parity with MCP-OSINTULT).
/// Respects <KEEP>...</KEEP> blocks which are passed through unmodified.
/// Stage order is significant: extractive compression first, lexical substitution last.
pub struct PromptOptimizer {
    strategies: Vec<Box<dyn OptimizationStrategy>>,
}

impl PromptOptimizer {
    pub fn new() -> Self {
        Self {
            strategies: vec![
                Box::new(ExtractiveCompressor),  // 1. Drop low-signal lines first
                Box::new(EntropyPruner),          // 2. Strip low-entropy adverbs
                Box::new(VerbosityReducer),       // 3. Collapse verbose phrases
                Box::new(ArticleStripper),        // 4. Remove articles
                Box::new(FillerRemover),          // 5. Remove filler words
                Box::new(SynonymMapper),          // 6. Abbreviate long technical terms
                Box::new(SuffixLemmatizer),       // 7. Strip -ing/-ed/-ly suffixes
                Box::new(PunctuationPruner),      // 8. Strip non-essential punctuation (Ultra only)
                Box::new(WenyanUltraStrategy),    // 9. Lexical CJK substitution (Ultra only)
                Box::new(Deduplicator),           // 10. Final dedup pass
            ],
        }
    }

    /// Optimizes `input` while preserving content inside `<KEEP>` tags verbatim.
    pub fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Off { return input.to_string(); }
        
        let keep_pattern = format!(
            r"{}(?s:.*?){}",
            regex::escape(PROTECTED_TAG_START),
            regex::escape(PROTECTED_TAG_END)
        );
        let re_keep = Regex::new(&keep_pattern).unwrap();

        let mut result = String::new();
        let mut last_pos = 0;

        for mat in re_keep.find_iter(input) {
            result.push_str(&self.optimize_block(&input[last_pos..mat.start()], level));
            result.push_str(mat.as_str());
            last_pos = mat.end();
        }
        result.push_str(&self.optimize_block(&input[last_pos..], level));
        result.trim().to_string()
    }

    fn optimize_block(&self, block: &str, level: OptimizationLevel) -> String {
        let mut current = block.to_string();
        for strategy in &self.strategies {
            current = strategy.optimize(&current, level);
        }
        current
    }

    /// Returns estimated token savings: (original_chars - optimized_chars) / 4.
    pub fn savings_tokens(original: &str, optimized: &str) -> u64 {
        let orig = original.len();
        let opt = optimized.len();
        if opt < orig { ((orig - opt) / 4) as u64 } else { 0 }
    }
}

pub static PROMPT_OPTIMIZER: Lazy<PromptOptimizer> = Lazy::new(PromptOptimizer::new);

// ─── ContextRanker ───────────────────────────────────────────────────────────

/// MMR-based context ranker. Selects the most relevant AND diverse set of files
/// for a given query within a token budget.
pub struct ContextRanker {
    cache: Mutex<HashMap<String, Vec<(String, f64)>>>,
}

impl ContextRanker {
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }

    /// Returns ranked file paths by relevance to `query`.
    /// - `token_budget`: max tokens to fill (default 32k)
    /// - `lambda`: MMR diversity weight 0.0 (pure diversity) – 1.0 (pure relevance). Default 0.65.
    pub fn rank_files(
        &self,
        query: &str,
        files: &[(String, String)],
        token_budget: Option<u64>,
        lambda: Option<f64>,
    ) -> Vec<(String, f64)> {
        let lambda = lambda.unwrap_or(0.65);
        let cache_key = format!("{}:{}:{:?}:{:.2}", query, files.len(), token_budget, lambda);

        if let Ok(cache) = self.cache.lock() {
            if let Some(hits) = cache.get(&cache_key) {
                return hits.clone();
            }
        }

        let query_terms: Vec<String> = query.to_lowercase()
            .split_whitespace().map(|s| s.to_string()).collect();

        let mut initial_scores: Vec<(String, String, f64)> = files.iter()
            .map(|(path, content)| {
                let mut score = 0.0;
                let pl = path.to_lowercase();
                let cl = content.to_lowercase();
                for term in &query_terms {
                    if pl.contains(term.as_str()) { score += 10.0; }
                    score += cl.matches(term.as_str()).count() as f64 * 0.5;
                }
                if path.ends_with(".rs") { score += 2.0; }
                if path.ends_with(".md") { score += 1.0; }
                // Recency boost
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

        let max_tokens = token_budget.unwrap_or(32_000);
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

            // Dependency boost: archivos importados por el seleccionado suben en ranking
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

        let result: Vec<(String, f64)> = selected.into_iter().map(|(p, _, s)| (p, s)).collect();

        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() > 50 { cache.clear(); }
            cache.insert(cache_key, result.clone());
        }

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

    /// Extrae nombres de módulos importados en código Rust para dependency boost.
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

pub static CONTEXT_RANKER: Lazy<ContextRanker> = Lazy::new(ContextRanker::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_reducer_no_hot_compile() {
        // Calling optimize() 100 times must not recompile regexes (static VERBOSITY_RULES)
        let opt = PromptOptimizer::new();
        for _ in 0..100 {
            let r = opt.optimize("in order to perform an audit due to the fact that it is important to", OptimizationLevel::Full);
            assert!(r.contains("audit"));
            assert!(!r.contains("in order to"));
        }
    }

    #[test]
    fn test_keep_tags_preserved() {
        let opt = PromptOptimizer::new();
        let input = "Please ensure that <KEEP>cargo build --release</KEEP> is executed.";
        let out = opt.optimize(input, OptimizationLevel::Full);
        assert!(out.contains("cargo build --release"));
    }

    #[test]
    fn test_synonym_mapper() {
        let opt = PromptOptimizer::new();
        let r = opt.optimize("vulnerability configuration infrastructure", OptimizationLevel::Full);
        assert!(r.contains("vuln"));
        assert!(r.contains("config"));
        assert!(r.contains("infra"));
    }

    #[test]
    fn test_savings_tokens() {
        let orig = "a".repeat(400);
        let opt = "a".repeat(200);
        assert_eq!(PromptOptimizer::savings_tokens(&orig, &opt), 50);
    }

    #[test]
    fn test_suffix_lemmatizer_skips_code() {
        let opt = PromptOptimizer::new();
        // Prose: suffixes stripped
        let prose = opt.optimize("executing scanning processing", OptimizationLevel::Full);
        assert!(!prose.contains("ing"), "suffixes must be stripped in prose");
        // Code line: must be preserved
        let code = opt.optimize("    let running = true;", OptimizationLevel::Full);
        assert!(code.contains("running"), "code lines must not be lemmatized");
    }

    #[test]
    fn test_wenyan_ultra_only_at_ultra_level() {
        let opt = PromptOptimizer::new();
        let input = "security audit vulnerability";
        let full = opt.optimize(input, OptimizationLevel::Full);
        // At Full level Wenyan must NOT activate
        assert!(!full.contains('安'), "Wenyan must not activate at Full level");
        assert!(!full.contains('查'), "Wenyan must not activate at Full level");
        let ultra = opt.optimize(input, OptimizationLevel::Ultra);
        // At Ultra level at least one substitution must occur
        assert!(ultra.contains('安') || ultra.contains('查') || ultra.contains('穴'),
            "Wenyan must activate at Ultra level");
    }

    #[test]
    fn test_punctuation_pruner_ultra_only() {
        let opt = PromptOptimizer::new();
        let input = "audit complete, security verified; no issues!";
        let full = opt.optimize(input, OptimizationLevel::Full);
        // Comma/semicolon may survive at Full (PunctuationPruner inactive)
        let ultra = opt.optimize(input, OptimizationLevel::Ultra);
        // At Ultra the punctuation pruner fires — commas/semicolons replaced by space
        assert!(!ultra.contains(',') && !ultra.contains(';'),
            "punctuation must be stripped at Ultra level");
    }

    #[test]
    fn test_entropy_pruner() {
        let opt = PromptOptimizer::new();
        let r = opt.optimize("basically the system is definitely vulnerable", OptimizationLevel::Full);
        assert!(!r.contains("basically"));
        assert!(!r.contains("definitely"));
        assert!(r.contains("vulnerable") || r.contains("vuln"));
    }

    #[test]
    fn test_pipeline_stage_count() {
        let opt = PromptOptimizer::new();
        assert_eq!(opt.strategies.len(), 10, "pipeline must have exactly 10 stages");
    }

    #[test]
    fn test_ranker_returns_relevant_first() {
        let files = vec![
            ("src/proxy.rs".to_string(), "pub struct ProxyManager;".to_string()),
            ("docs/audit.md".to_string(), "Security audit proxy module.".to_string()),
            ("src/main.rs".to_string(), "fn main() {}".to_string()),
        ];
        let scores = CONTEXT_RANKER.rank_files("proxy security", &files, None, None);
        assert!(!scores.is_empty());
        assert!(scores[0].0.contains("proxy") || scores[0].0.contains("audit"));
    }
}
