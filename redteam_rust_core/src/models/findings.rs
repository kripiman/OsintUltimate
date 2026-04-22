use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Restricted command execution without 'sh -c'. 
    SafeCommand,
    /// HTTP(S) request and pattern match. 
    HttpPayload,
    /// TCP connection check.
    TcpCheck,
    /// ICMP echo request.
    IcmpPing,
    /// Integration with Nuclei engine.
    NucleiTemplate,
    /// Human-provided verified exploit handover (Sovereign Mode).
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Evidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactical_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_analysis: Option<AIAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mitre_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackarch_category: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,
    pub timestamps: chrono::DateTime<chrono::Utc>,

    // Decepticon Adoption V2 Fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    pub cvss_version: String,           // default "4.0"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detection_notes: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consolidation_urgency: Option<ConsolidationUrgency>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_files: Vec<EvidenceFile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub objective_id: String,           // OBJ-xxx del OPPLAN
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent: String,                  // agente que descubrió el finding
    #[serde(default)]
    pub iteration: u32,                 // iteración del loop
    #[serde(default)]
    pub validation: ValidationMetadata,  // NUEVO V15: Pipeline Anti-Alucinación
}

impl Finding {
    pub fn new(
        id: &str,
        category: Category,
        severity: Severity,
        description: &str,
        evidence: serde_json::Value,
    ) -> Self {
        Self {
            id: id.to_string(),
            category,
            severity: severity.clone(),
            title: description.to_string(), // Default title to description
            description: description.to_string(),
            evidence: Evidence { 
                data: evidence,
                confidence: 0.5,
                verified: false,
            },
            tactical_path: None,
            parent_id: None,
            ai_analysis: None,
            mitre_attack: None,
            mitre_tags: Vec::new(),
            cvss_score: Some(crate::utils::cvss::Cvss40::calculate(&severity, 0.5)),
            blackarch_category: None,
            references: Vec::new(),
            timestamps: chrono::Utc::now(),
            cvss_vector: None,
            cvss_version: "4.0".to_string(),
            cwe: Vec::new(),
            detected: None,
            detection_notes: String::new(),
            consolidation_urgency: None,
            evidence_files: Vec::new(),
            objective_id: String::new(),
            agent: String::new(),
            iteration: 0,
            validation: ValidationMetadata::default(),
        }
    }

    pub fn with_tactical_path(mut self, tactical_path: &str) -> Self {
        self.tactical_path = Some(tactical_path.to_string());
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.parent_id = Some(parent_id.to_string());
        self
    }

    pub fn with_ai_analysis(mut self, analysis: AIAnalysis) -> Self {
        self.ai_analysis = Some(analysis);
        self
    }

    pub fn with_mitre_attack(mut self, tags: Vec<String>) -> Self {
        self.mitre_attack = Some(tags);
        self
    }

    pub fn with_cvss(mut self, score: f32) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn with_references(mut self, refs: Vec<String>) -> Self {
        self.references = refs;
        self
    }

    pub fn with_blackarch_category(mut self, category: &str) -> Self {
        self.blackarch_category = Some(category.to_string());
        self
    }

    pub fn with_cvss_vector(mut self, vector: &str) -> Self {
        self.cvss_vector = Some(vector.to_string());
        self
    }

    pub fn with_cwe(mut self, cwe: Vec<String>) -> Self {
        self.cwe = cwe;
        self
    }

    pub fn with_detection_status(mut self, detected: bool, notes: &str) -> Self {
        self.detected = Some(detected);
        self.detection_notes = notes.to_string();
        self
    }

    pub fn with_consolidation_urgency(mut self, urgency: ConsolidationUrgency) -> Self {
        self.consolidation_urgency = Some(urgency);
        self
    }

    pub fn with_evidence_file(mut self, file: EvidenceFile) -> Self {
        self.evidence_files.push(file);
        self
    }

    pub fn with_execution_context(mut self, objective_id: &str, agent: &str, iteration: u32) -> Self {
        self.objective_id = objective_id.to_string();
        self.agent = agent.to_string();
        self.iteration = iteration;
        self
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Finding: {}\n\n", self.title));
        md.push_str(&format!("**ID**: `{}`  \n", self.id));
        md.push_str(&format!("**Severity**: **{:?}**  \n", self.severity));
        md.push_str(&format!("**Category**: `{:?}`  \n", self.category));
        
        if let Some(score) = self.cvss_score {
            md.push_str(&format!("**CVSS Score**: `{}`  \n", score));
        }
        if let Some(ref vector) = self.cvss_vector {
            md.push_str(&format!("**CVSS Vector**: `{}` (`{}`)  \n", vector, self.cvss_version));
        }
        
        if let Some(det) = self.detected {
            md.push_str(&format!("**Status**: {}  \n", if det { "🔴 Detected" } else { "🟢 Not Detected" }));
        }
        
        if let Some(ref urgency) = self.consolidation_urgency {
            let prio_str = match urgency {
                ConsolidationUrgency::Immediate => "🚨 Immediate",
                ConsolidationUrgency::ShortTerm => "⚠️ Short-term",
                ConsolidationUrgency::LongTerm => "📅 Long-term",
            };
            md.push_str(&format!("**Consolidation Urgency**: {}  \n", prio_str));
        }
        
        md.push_str("\n## Description\n\n");
        md.push_str(&self.description);
        md.push_str("\n\n");

        if !self.cwe.is_empty() {
            md.push_str("## CWE\n\n");
            for cwe in &self.cwe {
                md.push_str(&format!("- [{0}](https://cwe.mitre.org/data/definitions/{1}.html)\n", cwe, cwe.replace("CWE-", "")));
            }
            md.push_str("\n");
        }

        if let Some(ref tags) = self.mitre_attack {
            md.push_str("## MITRE ATT&CK\n\n");
            for tag in tags {
                md.push_str(&format!("- `{}`\n", tag));
            }
            md.push_str("\n");
        }

        md.push_str("## Evidence\n\n");
        md.push_str("```json\n");
        md.push_str(&serde_json::to_string_pretty(&self.evidence.data).unwrap_or_default());
        md.push_str("\n```\n\n");

        if !self.evidence_files.is_empty() {
            md.push_str("### Evidence Files\n\n");
            md.push_str("| File Type | Path | SHA-256 | Collected At |\n");
            md.push_str("|---|---|---|---|\n");
            for file in &self.evidence_files {
                let sha_short = if file.sha256.len() > 8 { &file.sha256[..8] } else { &file.sha256 };
                md.push_str(&format!("| {} | `{}` | `{}` | {} |\n", 
                    file.evidence_type, file.path, sha_short, file.collected_at));
            }
            md.push_str("\n");
        }

        if let Some(ref tactical) = self.tactical_path {
            md.push_str("## Tactical Path\n\n");
            md.push_str(tactical);
            md.push_str("\n\n");
        }

        if !self.detection_notes.is_empty() {
            md.push_str("## Detection Notes\n\n");
            md.push_str(&self.detection_notes);
            md.push_str("\n\n");
        }

        md.push_str("## Context\n\n");
        if !self.objective_id.is_empty() {
            md.push_str(&format!("- **Objective**: `{}`\n", self.objective_id));
        }
        if !self.agent.is_empty() {
            md.push_str(&format!("- **Agent**: `{}`\n", self.agent));
        }
        if self.iteration > 0 {
            md.push_str(&format!("- **Iteration**: `{}`\n", self.iteration));
        }
        md.push_str(&format!("- **Timestamp**: `{}`\n", self.timestamps));

        md
    }
}
