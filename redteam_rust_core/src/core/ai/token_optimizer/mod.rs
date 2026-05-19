/// token_optimizer/mod.rs — Facade mod for token optimization.
/// Re-exports PromptOptimizer, ContextRanker, OptimizationLevel, and statics.
use std::collections::HashMap;
use regex::Regex;
use once_cell::sync::Lazy;

pub mod strategies;
pub mod optimizer;
pub mod ranker;

pub use optimizer::PromptOptimizer;
pub use ranker::ContextRanker;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OptimizationLevel {
    Off,
    Lite,
    #[default]
    Full,
    Ultra,
}

pub static PROMPT_OPTIMIZER: Lazy<PromptOptimizer> = Lazy::new(PromptOptimizer::new);
pub static CONTEXT_RANKER: Lazy<ContextRanker> = Lazy::new(ContextRanker::new);

pub(crate) const PROTECTED_TAG_START: &str = "<KEEP>";
pub(crate) const PROTECTED_TAG_END: &str = "</KEEP>";

// Shared lexical databases moved to mod.rs to satisfy sub-file LOC limits.
pub(crate) static WENYAN_MAP: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?i)\baudit\b").unwrap(), "查"), (Regex::new(r"(?i)\bsecurity\b").unwrap(), "安"),
    (Regex::new(r"(?i)\bsystem\b").unwrap(), "系"), (Regex::new(r"(?i)\bcode\b").unwrap(), "碼"),
    (Regex::new(r"(?i)\blogic\b").unwrap(), "理"), (Regex::new(r"(?i)\bnetwork\b").unwrap(), "網"),
    (Regex::new(r"(?i)\bprocess\b").unwrap(), "法"), (Regex::new(r"(?i)\buser\b").unwrap(), "客"),
    (Regex::new(r"(?i)\binput\b").unwrap(), "入"), (Regex::new(r"(?i)\boutput\b").unwrap(), "出"),
    (Regex::new(r"(?i)\barchitecture\b").unwrap(), "構"), (Regex::new(r"(?i)\bvulnerability\b").unwrap(), "穴"),
    (Regex::new(r"(?i)\binfrastructure\b").unwrap(), "基"), (Regex::new(r"(?i)\bsnapshot\b").unwrap(), "影"),
    (Regex::new(r"(?i)\bcontext\b").unwrap(), "境"), (Regex::new(r"(?i)\boptimiz\w+\b").unwrap(), "極"),
    (Regex::new(r"(?i)\bcritical\b").unwrap(), "危"), (Regex::new(r"(?i)\bexecut\w+\b").unwrap(), "行"),
    (Regex::new(r"(?i)\bperform\b").unwrap(), "行"), (Regex::new(r"(?i)\banalysis\b").unwrap(), "析"),
]);

pub(crate) static VERBOSITY_RULES: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| vec![
    (Regex::new(r"(?i)in order to").unwrap(), "to"), (Regex::new(r"(?i)due to the fact that").unwrap(), "because"),
    (Regex::new(r"(?i)at this point in time").unwrap(), "now"), (Regex::new(r"(?i)has the ability to").unwrap(), "can"),
    (Regex::new(r"(?i)it is important to").unwrap(), "must"), (Regex::new(r"(?i)take into account").unwrap(), "consider"),
    (Regex::new(r"(?i)a large number of").unwrap(), "many"), (Regex::new(r"(?i)prior to").unwrap(), "before"),
    (Regex::new(r"(?i)subsequent to").unwrap(), "after"), (Regex::new(r"(?i)in the event that").unwrap(), "if"),
    (Regex::new(r"(?i)in spite of the fact that").unwrap(), "although"), (Regex::new(r"(?i)it is possible that").unwrap(), "maybe"),
    (Regex::new(r"(?i)it is essential that").unwrap(), "must"), (Regex::new(r"(?i)in the near future").unwrap(), "soon"),
    (Regex::new(r"(?i)at the present time").unwrap(), "now"), (Regex::new(r"(?i)perform an audit").unwrap(), "audit"),
    (Regex::new(r"(?i)conduct a review").unwrap(), "review"),
]);

pub(crate) static SYNONYMS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let pairs = [
        ("asynchronous", "async"), ("synchronous", "sync"), ("development", "dev"),
        ("vulnerability", "vuln"), ("authentication", "auth"), ("authorization", "auth"),
        ("configuration", "config"), ("infrastructure", "infra"), ("architecture", "arch"),
        ("documentation", "doc"), ("implementation", "impl"), ("information", "info"),
        ("optimization", "opt"), ("performance", "perf"), ("application", "app"),
        ("repository", "repo"), ("dependency", "dep"), ("dependencies", "deps"),
        ("security", "sec")
    ];
    for (k, v) in pairs { m.insert(k, v); }
    m
});
