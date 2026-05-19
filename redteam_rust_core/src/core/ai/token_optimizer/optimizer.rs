/// token_optimizer/optimizer.rs — PromptOptimizer implementation and its unit tests.
use regex::Regex;
use super::strategies::*;
use super::OptimizationLevel;

pub struct PromptOptimizer {
    strategies: Vec<Box<dyn OptimizationStrategy>>,
}

impl Default for PromptOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptOptimizer {
    pub fn new() -> Self {
        Self {
            strategies: vec![
                Box::new(ExtractiveCompressor),
                Box::new(EntropyPruner),
                Box::new(VerbosityReducer),
                Box::new(ArticleStripper),
                Box::new(FillerRemover),
                Box::new(SynonymMapper),
                Box::new(SuffixLemmatizer),
                Box::new(PunctuationPruner),
                Box::new(WenyanUltraStrategy),
                Box::new(Deduplicator),
            ],
        }
    }

    pub fn optimize(&self, input: &str, level: OptimizationLevel) -> String {
        if level == OptimizationLevel::Off { return input.to_string(); }
        
        let keep_pattern = format!(
            r"{}(?s:.*?){}",
            regex::escape(super::PROTECTED_TAG_START),
            regex::escape(super::PROTECTED_TAG_END)
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

    pub fn savings_tokens(original: &str, optimized: &str) -> u64 {
        let orig = original.len();
        let opt = optimized.len();
        if opt < orig { ((orig - opt) / 4) as u64 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verbosity_reducer_no_hot_compile() {
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
        let prose = opt.optimize("executing scanning processing", OptimizationLevel::Full);
        assert!(!prose.contains("ing"), "suffixes must be stripped in prose");
        let code = opt.optimize("    let running = true;", OptimizationLevel::Full);
        assert!(code.contains("running"), "code lines must not be lemmatized");
    }

    #[test]
    fn test_wenyan_ultra_only_at_ultra_level() {
        let opt = PromptOptimizer::new();
        let input = "security audit vulnerability";
        let full = opt.optimize(input, OptimizationLevel::Full);
        assert!(!full.contains('安'), "Wenyan must not activate at Full level");
        assert!(!full.contains('查'), "Wenyan must not activate at Full level");
        let ultra = opt.optimize(input, OptimizationLevel::Ultra);
        assert!(ultra.contains('安') || ultra.contains('查') || ultra.contains('穴'),
            "Wenyan must activate at Ultra level");
    }

    #[test]
    fn test_punctuation_pruner_ultra_only() {
        let opt = PromptOptimizer::new();
        let input = "audit complete, security verified; no issues!";
        let ultra = opt.optimize(input, OptimizationLevel::Ultra);
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
}
