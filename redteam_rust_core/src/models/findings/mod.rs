use serde::{Deserialize, Serialize};
use std::ops::Deref;

pub mod classification;
pub mod core_fields;
pub mod enrichment;
pub mod evidence;

pub use classification::{Severity, Category, ConsolidationUrgency};
pub use core_fields::{CoreFinding, ExecutionContext};
pub use enrichment::{AIAnalysis, FindingEnrichment, PocStrategy, ValidatedPoc, PocDefinition, TokenUsage};
pub use evidence::{Evidence, EvidenceFile, FindingEvidence, ValidationMetadata, ValidationStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(flatten)]
    pub core: CoreFinding,
    pub evidence: FindingEvidence,
    pub enrichment: FindingEnrichment,
    pub context: ExecutionContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationMetadata>,
}

impl Deref for Finding {
    type Target = CoreFinding;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl Finding {
    pub fn builder(id: &str, category: Category, severity: Severity, description: &str) -> FindingBuilder {
        FindingBuilder::new(id, category, severity, description)
    }

    pub fn pattern_signature(&self) -> String {
        format!("{:?}:{:?}:{}", self.core.category, self.core.severity, self.core.id)
    }

    pub fn new(id: &str, category: Category, severity: Severity, description: &str, evidence: serde_json::Value) -> Self {
        Self::builder(id, category, severity, description)
            .with_evidence(evidence)
            .build()
    }

    pub fn with_ai_analysis(mut self, analysis: AIAnalysis) -> Self {
        self.enrichment.ai_analysis = Some(analysis);
        self
    }

    pub fn with_mitre_attack(mut self, tags: Vec<String>) -> Self {
        self.enrichment.mitre_attack = Some(tags);
        self
    }

    pub fn with_tactical_path(mut self, path: &str) -> Self {
        self.core.tactical_path = Some(path.to_string());
        self
    }

    pub fn with_parent(mut self, id: &str) -> Self {
        self.core.parent_id = Some(id.to_string());
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.enrichment.cvss_score = Some(score);
        self
    }

    pub fn with_cvss_vector(mut self, vector: &str) -> Self {
        self.enrichment.cvss_vector = Some(vector.to_string());
        self
    }

    pub fn with_cwe(mut self, cwe: Vec<String>) -> Self {
        self.enrichment.cwe = cwe;
        self
    }

    pub fn with_consolidation_urgency(mut self, urgency: ConsolidationUrgency) -> Self {
        self.enrichment.consolidation_urgency = Some(urgency);
        self
    }

    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.enrichment.references = refs;
        self
    }

    pub fn with_blackarch_category(mut self, category: &str) -> Self {
        self.enrichment.blackarch_category = Some(category.to_string());
        self
    }

    pub fn with_execution_context(mut self, objective_id: &str, agent: &str, iteration: u32) -> Self {
        self.context.objective_id = objective_id.to_string();
        self.context.agent = agent.to_string();
        self.context.iteration = iteration;
        self
    }

    pub fn enrich_with_cvss(&mut self) {
        if self.enrichment.cvss_score.is_none() {
            let cvss = crate::utils::cvss::Cvss31::from_severity(&self.core.severity);
            self.enrichment.cvss_score = Some(cvss.score);
            self.enrichment.cvss_vector = Some(cvss.vector);
            self.enrichment.cvss_version = "3.1".to_string();
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Finding: {}\n\n", self.core.title));
        md.push_str(&format!("**ID**: `{}`  \n", self.core.id));
        md.push_str(&format!("**Severity**: **{:?}**  \n", self.core.severity));
        md.push_str(&format!("**Category**: `{:?}`  \n", self.core.category));
        
        if let Some(score) = self.enrichment.cvss_score {
            md.push_str(&format!("**CVSS Score**: `{}`  \n", score));
        }
        if let Some(ref vector) = self.enrichment.cvss_vector {
            md.push_str(&format!("**CVSS Vector**: `{}` (`{}`)  \n", vector, self.enrichment.cvss_version));
        }
        
        if let Some(det) = self.context.detected {
            md.push_str(&format!("**Status**: {}  \n", if det { "🔴 Detected" } else { "🟢 Not Detected" }));
        }

        if let Some(ref urgency) = self.enrichment.consolidation_urgency {
            let emoji = match urgency {
                ConsolidationUrgency::Immediate => "🚨 Immediate",
                ConsolidationUrgency::ShortTerm => "⚠️ ShortTerm",
                ConsolidationUrgency::LongTerm => "📅 LongTerm",
            };
            md.push_str(&format!("**Consolidation Urgency**: {}  \n", emoji));
        }
        
        md.push_str("\n## Description\n\n");
        md.push_str(&self.core.description);
        md.push_str("\n\n");

        if !self.enrichment.cwe.is_empty() {
            md.push_str("## CWE\n\n");
            for cwe in &self.enrichment.cwe {
                md.push_str(&format!("- [{0}](https://cwe.mitre.org/data/definitions/{1}.html)\n", cwe, cwe.replace("CWE-", "")));
            }
            md.push('\n');
        }

        if let Some(ref tags) = self.enrichment.mitre_attack {
            md.push_str("## MITRE ATT&CK\n\n");
            for tag in tags {
                md.push_str(&format!("- `{}`\n", tag));
            }
            md.push('\n');
        }

        if let Some(ref ev) = self.evidence.primary {
            md.push_str("## Evidence\n\n");
            md.push_str("```json\n");
            md.push_str(&serde_json::to_string_pretty(&ev.data).unwrap_or_default());
            md.push_str("\n```\n\n");
        }

        if !self.evidence.files.is_empty() {
            md.push_str("### Evidence Files\n\n");
            md.push_str("| File Type | Path | SHA-256 | Collected At |\n");
            md.push_str("|---|---|---|---|\n");
            for file in &self.evidence.files {
                let sha_short = if file.sha256.len() > 8 { &file.sha256[..8] } else { &file.sha256 };
                md.push_str(&format!("| {} | `{}` | `{}` | {} |\n", 
                    file.evidence_type, file.path, sha_short, file.collected_at));
            }
            md.push('\n');
        }

        md.push_str("## Context\n\n");
        if !self.context.objective_id.is_empty() {
            md.push_str(&format!("- **Objective**: `{}`\n", self.context.objective_id));
        }
        if !self.context.agent.is_empty() {
            md.push_str(&format!("- **Agent**: `{}`\n", self.context.agent));
        }
        md.push_str(&format!("- **Timestamp**: `{}`\n", self.core.timestamps));

        md
    }
}

pub struct FindingBuilder {
    core: CoreFinding,
    evidence: FindingEvidence,
    enrichment: FindingEnrichment,
    context: ExecutionContext,
    validation: Option<ValidationMetadata>,
}

impl FindingBuilder {
    pub fn new(id: &str, category: Category, severity: Severity, description: &str) -> Self {
        Self {
            core: CoreFinding {
                id: id.to_string(),
                category,
                severity: severity.clone(),
                title: description.to_string(),
                description: description.to_string(),
                timestamps: chrono::Utc::now(),
                tactical_path: None,
                parent_id: None,
                version: 0,
                target: None,
                source_plugin: None,
                scope_id: String::new(),
                reactive_depth: 0,
                attack_path: None,
            },
            evidence: FindingEvidence::default(),
            enrichment: FindingEnrichment {
                cvss_version: "4.0".to_string(),
                ..Default::default()
            },
            context: ExecutionContext::default(),
            validation: None,
        }
    }

    pub fn with_evidence(mut self, data: serde_json::Value) -> Self {
        self.evidence.primary = Some(Evidence {
            data,
            confidence: 0.5,
            verified: false,
        });
        self
    }

    pub fn with_ai_analysis(mut self, analysis: AIAnalysis) -> Self {
        self.enrichment.ai_analysis = Some(analysis);
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.enrichment.cvss_score = Some(score);
        self
    }

    pub fn with_execution_context(mut self, objective_id: &str, agent: &str, iteration: u32) -> Self {
        self.context.objective_id = objective_id.to_string();
        self.context.agent = agent.to_string();
        self.context.iteration = iteration;
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            core: self.core,
            evidence: self.evidence,
            enrichment: self.enrichment,
            context: self.context,
            validation: self.validation,
        }
    }
}
