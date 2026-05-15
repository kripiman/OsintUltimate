use crate::models::{Finding, Severity};

/// A lightweight filter to reduce noise and false positives in findings
pub struct FalsePositiveFilter {
    noise_threshold: f32, // Findings with a noise score above this are considered FPs
}

impl FalsePositiveFilter {
    pub fn new(noise_threshold: f32) -> Self {
        Self { noise_threshold }
    }

    /// Evaluates a finding and returns true if it should be KEPT, false if it's a FALSE POSITIVE
    pub fn evaluate(&self, finding: &Finding) -> bool {
        crate::utils::telemetry::METRIC_FINDINGS_IN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let score = self.calculate_noise_score(finding);
        let keep = score < self.noise_threshold;
        
        if !keep {
            crate::utils::telemetry::METRIC_FPF_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::debug!("🛡️ FPF: Finding {} dropped (Noise Score: {:.2})", finding.core.id, score);
        }
        
        keep
    }

    /// Calculates a heuristic "Noise Score" (0.0 to 1.0)
    /// Higher score = More likely to be noise/false positive
    fn calculate_noise_score(&self, finding: &Finding) -> f32 {
        let mut score = 0.0;

        // 1. Evidence Confidence (Inverse relationship)
        let confidence = finding.evidence.primary.as_ref().map(|e| e.confidence).unwrap_or(0.5);
        let conf_factor = 1.0 - confidence.clamp(0.0, 1.0);
        score += conf_factor * 0.4; // 40% weight

        // 2. Keyword Heuristics in Description/Title
        let text = format!("{} {}", finding.core.title, finding.core.description).to_lowercase();
        let noise_keywords = [
            "timeout", "connection reset", "404 not found", "403 forbidden",
            "potential", "possible", "unconfirmed", "generic", "unknown version"
        ];
        
        let mut keyword_hits = 0;
        for kw in &noise_keywords {
            if text.contains(kw) {
                keyword_hits += 1;
            }
        }
        
        if keyword_hits > 0 {
             score += (keyword_hits as f32 * 0.15).clamp(0.0, 0.3); // max 30% weight
        }

        // 3. Category & Severity Context
        match finding.core.severity {
            Severity::Info | Severity::Low => score += 0.2, // Low severity is naturally noisier
            Severity::Critical | Severity::High => score -= 0.1, // High severity gets benefit of the doubt
            _ => {}
        }

        // 4. Evidence Verification
        let verified = finding.evidence.primary.as_ref().map(|e| e.verified).unwrap_or(false);
        if verified {
            score -= 0.3; // Verified findings are heavily discounted as noise
        }
        
        // 5. Verification vs AI Analysis
        if finding.enrichment.ai_analysis.is_none() && confidence < 0.6 {
            score += 0.1; 
        }

        score.clamp(0.0, 1.0)
    }
}

impl Default for FalsePositiveFilter {
    fn default() -> Self {
        Self::new(0.65) // Default threshold: 65% noise score to drop
    }
}
