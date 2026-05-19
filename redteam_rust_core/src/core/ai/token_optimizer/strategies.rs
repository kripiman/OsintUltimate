/// token_optimizer/strategies.rs — 10 OptimizationStrategy implementations.
use std::collections::HashSet;
use regex::Regex;
use once_cell::sync::Lazy;
use super::OptimizationLevel;

static RE_ARTICLES: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(the|a|an)\b").unwrap());
static RE_SUFFIX_ING: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ing\b").unwrap());
static RE_SUFFIX_ED:  Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ed\b").unwrap());
static RE_SUFFIX_LY:  Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\w{3,})ly\b").unwrap());
static RE_PUNCTUATION: Lazy<Regex> = Lazy::new(|| Regex::new(r"[,;!?](?:\s|$)").unwrap());

static ENTROPY_PRUNER: Lazy<Regex> = Lazy::new(|| {
    let w = ["basically", "essentially", "actually", "literally", "simply", "really", "very", "just", "quite", "rather", "extremely", "totally", "completely", "highly", "largely", "mainly", "mostly", "certainly", "definitely", "probably", "possibly"];
    Regex::new(&format!(r"(?i)\b({})\b\s?", w.join("|"))).unwrap()
});

static FILLERS: Lazy<Regex> = Lazy::new(|| {
    let w = ["please", "kindly", "just", "very", "really", "basically", "actually", "ensure", "simply", "essentially", "highly", "extremely", "total", "literally", "quite", "rather", "certainly", "definitely", "completely", "largely", "mainly", "mostly"];
    Regex::new(&format!(r"(?i)\b({})\b\s?", w.join("|"))).unwrap()
});

pub(crate) trait OptimizationStrategy: Send + Sync {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String;
}

pub(crate) struct ArticleStripper;
impl OptimizationStrategy for ArticleStripper {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        RE_ARTICLES.replace_all(input, "").to_string()
    }
}

pub(crate) struct FillerRemover;
impl OptimizationStrategy for FillerRemover {
    fn optimize(&self, input: &str, _level: OptimizationLevel) -> String {
        FILLERS.replace_all(input, "").to_string()
    }
}

pub(crate) struct VerbosityReducer;
impl OptimizationStrategy for VerbosityReducer {
    fn optimize(&self, input: &str, _level: OptimizationLevel) -> String {
        let mut res = input.to_string();
        for (re, rep) in super::VERBOSITY_RULES.iter() {
            res = re.replace_all(&res, *rep).to_string();
        }
        res
    }
}

pub(crate) struct SynonymMapper;
impl OptimizationStrategy for SynonymMapper {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        input.split_whitespace()
            .map(|word| {
                let lower = word.to_lowercase();
                let clean = lower.trim_matches(|c: char| !c.is_alphanumeric());
                let mapping = if level == OptimizationLevel::Ultra {
                    super::SYNONYMS.get(clean)
                } else {
                    super::SYNONYMS.get(clean).filter(|&&s| s.len() < clean.len())
                };
                mapping.map(|&s| s.to_string()).unwrap_or_else(|| word.to_string())
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub(crate) struct ExtractiveCompressor;
impl ExtractiveCompressor {
    fn score_line(line: &str) -> f32 {
        static TECH_KW: &[&str] = &["proxy", "egress", "token", "payload", "audit", "security", "infra", "ghost", "strike", "breach", "sovereign", "stealth", "vuln", "config", "impl", "arch", "async", "sync", "error", "critical", "warning"];
        let lower = line.to_lowercase();
        let mut score: f32 = TECH_KW.iter().filter(|&&kw| lower.contains(kw)).count() as f32;
        if score == 0.0 && line.len() > 50 { score -= 0.5; }
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
        let mut scored: Vec<(usize, f32)> = lines.iter().enumerate().map(|(i, &l)| (i, Self::score_line(l))).collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let kept: HashSet<usize> = scored.iter().take(keep_count).map(|&(i, _)| i).collect();
        lines.iter().enumerate()
            .filter(|(i, l)| kept.contains(i) || l.starts_with('#') || (level != OptimizationLevel::Ultra && l.starts_with('-')))
            .map(|(_, &l)| l)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub(crate) struct SuffixLemmatizer;
impl OptimizationStrategy for SuffixLemmatizer {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        input.lines().map(|line| {
            let trimmed = line.trim_start();
            let is_code = trimmed.starts_with("fn ") || trimmed.starts_with("let ") ||
                          trimmed.starts_with("pub ") || trimmed.starts_with("impl ") || 
                          trimmed.starts_with("struct ") || line.contains("::");
            if is_code { return line.to_string(); }
            let s = RE_SUFFIX_ING.replace_all(line, "$1");
            let s = RE_SUFFIX_ED.replace_all(&s, "$1");
            RE_SUFFIX_LY.replace_all(&s, "$1").to_string()
        }).collect::<Vec<_>>().join("\n")
    }
}

pub(crate) struct EntropyPruner;
impl OptimizationStrategy for EntropyPruner {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Lite { return input.to_string(); }
        ENTROPY_PRUNER.replace_all(input, "").to_string()
    }
}

pub(crate) struct PunctuationPruner;
impl OptimizationStrategy for PunctuationPruner {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level != OptimizationLevel::Ultra { return input.to_string(); }
        RE_PUNCTUATION.replace_all(input, " ").to_string()
    }
}

pub(crate) struct WenyanUltraStrategy;
impl OptimizationStrategy for WenyanUltraStrategy {
    fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level != OptimizationLevel::Ultra { return input.to_string(); }
        let mut res = input.to_string();
        for (re, glyph) in super::WENYAN_MAP.iter() {
            res = re.replace_all(&res, *glyph).to_string();
        }
        res
    }
}

pub(crate) struct Deduplicator;
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
