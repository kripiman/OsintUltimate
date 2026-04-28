use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ExposedAsset,
    Vulnerability,
    Misconfiguration,
    CredentialLeak,
    TechnologyStack,
    NetworkPort,
    Recon,
    Scanning,
    Availability,
    SCA,
    PostureAudit,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationUrgency {
    Immediate,   // 0-7 days
    ShortTerm,   // 30 days
    LongTerm,    // 90+ days
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    #[default]
    Unverified,
    Verified,
    Suspicious,
    PseudoFalse,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationMetadata {
    pub status: ValidationStatus,
    pub confidence_score: f32, // 0.0 - 1.0
    pub judge_notes: String,
    pub negative_control_passed: bool,
    pub proof_of_execution: Option<String>,
    pub validated_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub evidence_type: String,  // screenshot, http-request, terminal-log, scan-output
    pub path: String,           // path relativo al workspace
    pub description: String,
    pub sha256: String,         // chain-of-custody
    pub collected_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(flatten)]
    pub data: serde_json::Value,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub verified: bool,
}

fn default_confidence() -> f32 { 0.5 }

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PocStrategy {
    SafeCommand,
    HttpPayload,
    TcpCheck,
    IcmpPing,
    NucleiTemplate,
    HumanVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidatedPoc {
    Nmap { 
        port: u16, 
        flags: Vec<String> 
    },
    Curl { 
        path: String, 
        headers: Vec<(String, String)> 
    },
    Ping,
    Dig,
    TcpConnect { 
        port: u16 
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocDefinition {
    pub strategy: PocStrategy,
    pub payload: String,
    pub expected_pattern: String,
    #[serde(default)]
    pub is_intrusive: bool,
    #[serde(default)]
    pub complexity_score: u8, // 0-100 rating
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysis {
    pub summary: String,
    pub impact: String,
    pub stealth_notes: String,
    pub risk_score: u8,
    pub confidence: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    pub exploit_path: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poc: Option<PocDefinition>,
    #[serde(default)]
    pub usage: TokenUsage,
}

// --- MODULAR COMPONENTS ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreFinding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub timestamps: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingEvidence {
    pub evidence: Option<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingEnrichment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<AIAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mitre_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cvss_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackarch_category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutionContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub objective_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,
    #[serde(default)]
    pub iteration: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detection_notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consolidation_urgency: Option<ConsolidationUrgency>,
    #[serde(default)]
    pub validation: ValidationMetadata,
}

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

        if let Some(ref ev) = self.evidence.evidence {
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
        self.evidence.evidence = Some(Evidence {
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
