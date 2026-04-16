use super::types::CavemanLevel;

/// V14.1 Sovereign Token Optimization: The Caveman Engine.
/// Inspired by JuliusBrussee/caveman Wenyan techniques.
pub struct CavemanOptimizer;

impl CavemanOptimizer {
    /// Wraps a system prompt with caveman/wenyan instructions based on the level.
    pub fn optimize_prompt(instruction: &str, level: CavemanLevel) -> String {
        if level == CavemanLevel::Off {
            return instruction.to_string();
        }

        let caveman_meta = match level {
            CavemanLevel::Lite => 
                "Respond terse like smart caveman. No filler/hedging. Keep articles + full sentences. Professional but tight. TECHNICAL ACCURACY 100%.",
            CavemanLevel::Full => 
                "Respond terse like smart caveman. Drop articles (a/an/the), filler (just/really/basically), pleasantries. Fragments OK. Short synonyms. Pattern: [thing] [action] [reason]. [next step].",
            CavemanLevel::Ultra => 
                "Respond ultra-terse. Telegraphic. Abbreviate (DB/auth/config/req/res/fn/impl). Strip conjunctions. Arrows for causality (X -> Y). One word if enough. TECHNICAL ACCURACY 100%.",
            CavemanLevel::WenyanUltra => 
                "Respond in FULL Wenyan (Classical Chinese - 文言文). Maximum classical terseness. 90% char reduction. Use classical particles (之/乃/為/其). TECHNICAL ACCURACY 100%.",
            _ => "Respond terse like smart caveman.",
        };

        format!(
            "{}\n\n## CAVEMAN PROTOCOL ACTIVE\n{}\nACTIVE EVERY RESPONSE. Code blocks unchanged. Errors quoted exact.",
            instruction,
            caveman_meta
        )
    }

    /// Provides a human-readable bridge for ApprovalGates.
    /// This pivots the AI back to English or Spanish for human interaction.
    pub fn pivot_to_human_readable(instruction: &str, prefer_spanish: bool) -> String {
        let lang_note = if prefer_spanish {
            "Respond in clear, professional SPANISH (Español)."
        } else {
            "Respond in clear, professional ENGLISH."
        };

        format!(
            "{}\n\n## HUMAN INTERACTION OVERRIDE\nDO NOT USE CAVEMAN/WENYAN FOR THIS RESPONSE. \
            The human operator needs to validate this or create a script. \
            {} Explain logic, risks, and next steps in detail. Technical terms exact.",
            instruction,
            lang_note
        )
    }
}
