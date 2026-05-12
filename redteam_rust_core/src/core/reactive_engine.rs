use crate::models::{Finding, TargetHost};
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use dashmap::DashSet;
use std::sync::Arc;
use tracing::debug;
use crate::models::constants::*;
use std::sync::LazyLock;
use std::collections::HashMap;

static COMPILED_REGEXES: LazyLock<HashMap<&'static str, regex::Regex>> = LazyLock::new(|| {
    get_all_rules().into_iter()
        .filter_map(|rule| {
            if let ContextExtractor::RegexMatch { pattern } = rule.extractor {
                Some((pattern, regex::Regex::new(pattern).expect("Invalid regex in rule")))
            } else {
                None
            }
        })
        .collect()
});

/// 觸發條件：單一ID或多ID聯集
#[derive(Clone, Debug)]
pub enum RuleTrigger {
    Single(&'static str),
    AnyOf(&'static [&'static str]),
}

impl RuleTrigger {
    pub fn matches(&self, finding_id: &str) -> bool {
        match self {
            RuleTrigger::Single(id) => *id == finding_id,
            RuleTrigger::AnyOf(ids) => ids.iter().any(|&id| id == finding_id),
        }
    }
}

/// 鏈的上下文萃取與額外過濾策略
#[derive(Clone, Debug)]
pub enum ContextExtractor {
    /// 從 evidence.data["url"] 取值，注入 extra_data[target_key]
    EvidenceField { source_key: &'static str, target_key: &'static str },
    /// 從 evidence.data["parameters"] 取陣列，注入 extra_data[target_key]  
    EvidenceArray { source_key: &'static str, target_key: &'static str },
    /// 無上下文需求，直接傳入原 target
    PassThrough,
    /// 基於 evidence 文本的關鍵字匹配 (OR)
    KeywordMatch { keywords: &'static [&'static str] },
    /// 基於正則匹配 (Mobile APK 鏈)
    RegexMatch { pattern: &'static str },
    /// 複合條件：關鍵字 (OR) 且 包含端點 (OR) (AI 鏈)
    KeywordAndEndpoint {
        keywords: &'static [&'static str],
        endpoints: &'static [&'static str],
    },
}

#[derive(Clone, Debug)]
pub struct ReactiveRule {
    pub trigger: RuleTrigger,
    pub chain_plugins: &'static [&'static str],
    pub extractor: ContextExtractor,
}

const BASE_RULES: &[ReactiveRule] = &[
    // 1. SSTI -> Commix
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_SSTI), 
        chain_plugins: &[PLUGIN_COMMIX],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "discovered_urls" } 
    },
    // 2. SBOM -> Grype/Cosign
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_SBOM_INVENTORY), 
        chain_plugins: &[PLUGIN_GRYPE, PLUGIN_COSIGN],
        extractor: ContextExtractor::PassThrough 
    },
    // 3. GraphQL -> GraphW00f/Schemathesis/CrackQL
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_GRAPHQL_INTROSPECTION),
        chain_plugins: &[PLUGIN_GRAPHW00F, PLUGIN_SCHEMATHESIS, PLUGIN_CRACKQL],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "api_schema_url" } 
    },
    // 4. JS Discovery -> Retire/SourceMapper  
    ReactiveRule { 
        trigger: RuleTrigger::Single("JS-FILES-DISCOVERED"), 
        chain_plugins: &["retire", "sourcemapper"],
        extractor: ContextExtractor::PassThrough 
    },
    // 5. Hidden Params -> SqlMap
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_HIDDEN_PARAMS), 
        chain_plugins: &[PLUGIN_SQLMAP],
        extractor: ContextExtractor::EvidenceArray { source_key: "parameters", target_key: "injected_parameters" } 
    },
    // 9. Source Code -> Semgrep
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_SOURCE_CODE_EXPOSED), 
        chain_plugins: &[PLUGIN_SEMGREP],
        extractor: ContextExtractor::PassThrough 
    },
    // 10. Deserialization -> GadgetDetector (Covers both ID variants)
    ReactiveRule { 
        trigger: RuleTrigger::AnyOf(&[FINDING_JAVA_SERIAL, FINDING_OBJECT_INJECTION]),
        chain_plugins: &[PLUGIN_DESERIALIZATION],
        extractor: ContextExtractor::PassThrough 
    },
];

#[cfg(feature = "sovereign")]
const SOVEREIGN_RULES: &[ReactiveRule] = &[
    // 6. Mobile APK -> MobSF chain
    ReactiveRule { 
        trigger: RuleTrigger::AnyOf(&[FINDING_KATANA_ENDPOINT, FINDING_WAYMORE_URL, FINDING_JS_ENDPOINT]),
        chain_plugins: &[PLUGIN_MOBSF, PLUGIN_APKLEAKS, PLUGIN_APKTOOL, PLUGIN_JADX, PLUGIN_DROZER, PLUGIN_FRIDA, PLUGIN_OBJECTION, PLUGIN_MARIANA_TRENCH],
        extractor: ContextExtractor::RegexMatch { pattern: r"\.apk($|\?)" } 
    },
    // 7. Cloud Infra -> KubeBench chain
    ReactiveRule { 
        trigger: RuleTrigger::AnyOf(&[FINDING_TECH_STACK, "NSE-SCRIPT"]),
        chain_plugins: &[PLUGIN_KUBE_BENCH, PLUGIN_KUBESCAPE, PLUGIN_PROWLER, PLUGIN_SCOUTSUITE],
        extractor: ContextExtractor::KeywordMatch { keywords: &["kubernetes", "k8s", "s3-bucket", "aws-metadata", "gcp-identity", "azure-storage", "lambda", "fargate"] } 
    },
    // 8. AI/LLM -> Garak chain
    ReactiveRule { 
        trigger: RuleTrigger::AnyOf(&[FINDING_TECH_STACK, FINDING_JS_ENDPOINT]),
        chain_plugins: &[PLUGIN_GARAK, PLUGIN_PROMPTMAP, PLUGIN_LLMFUZZER],
        extractor: ContextExtractor::KeywordAndEndpoint {
            keywords: &["openai", "anthropic", "ollama", "vllm", "mistral", "llama", "langchain"],
            endpoints: &["/v1/chat/completions", "api.openai.com", ":11434"]
        } 
    },
];

pub fn get_all_rules() -> Vec<ReactiveRule> {
    let mut rules = BASE_RULES.to_vec();
    #[cfg(feature = "sovereign")]
    {
        rules.extend_from_slice(SOVEREIGN_RULES);
    }
    rules
}

pub async fn evaluate(
    rules: &[ReactiveRule],
    findings: &[Finding],
    target: &TargetHost,
    plugins: &[Box<dyn ScannerPlugin>],
    layer_policy: &ScanLayerPolicy,
    approval_gate: &ApprovalGate,
    fired_chains: &DashSet<String>,
) -> Vec<Finding> {
    let mut extra_findings = Vec::new();

    for rule in rules {
        // Find if any existing finding matches the trigger
        let trigger_findings: Vec<&Finding> = findings.iter()
            .filter(|f| rule.trigger.matches(&f.core.id))
            .collect();

        for f in trigger_findings {
            // Apply extractor and check if we should fire
            let mut reactive_snapshot = target.clone();
            let mut should_fire = false;

            match &rule.extractor {
                ContextExtractor::EvidenceField { source_key, target_key } => {
                    if let Some(val) = f.evidence.evidence.as_ref()
                        .and_then(|e| e.data.get(*source_key))
                        .cloned() 
                    {
                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                            .as_object_mut()
                            .and_then(|obj| obj.insert(target_key.to_string(), val));
                        should_fire = true;
                    }
                }
                ContextExtractor::EvidenceArray { source_key, target_key } => {
                    if let Some(params) = f.evidence.evidence.as_ref()
                        .and_then(|e| e.data.get(*source_key))
                        .and_then(|p| p.as_array()) 
                    {
                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                            .as_object_mut()
                            .and_then(|obj| obj.insert(target_key.to_string(), serde_json::json!(params)));
                        should_fire = true;
                    }
                }
                ContextExtractor::PassThrough => {
                    should_fire = true;
                }
                ContextExtractor::KeywordMatch { keywords } => {
                    if let Some(evidence) = f.evidence.evidence.as_ref() {
                        let content = evidence.data.to_string().to_lowercase();
                        if keywords.iter().any(|&k| content.contains(k)) {
                            should_fire = true;
                        }
                    }
                }
                ContextExtractor::RegexMatch { pattern } => {
                    if let Some(re) = COMPILED_REGEXES.get(*pattern) {
                        if let Some(evidence) = f.evidence.evidence.as_ref() {
                            let content = evidence.data.to_string();
                            if re.is_match(&content) {
                                should_fire = true;
                            }
                        }
                    } else {
                        tracing::warn!("Regex pattern '{}' was not pre-compiled!", pattern);
                    }
                }
                ContextExtractor::KeywordAndEndpoint { keywords, endpoints } => {
                    if let Some(evidence) = f.evidence.evidence.as_ref() {
                        let content = evidence.data.to_string().to_lowercase();
                        let has_keyword = keywords.iter().any(|&k| content.contains(k));
                        let has_endpoint = endpoints.iter().any(|&e| content.contains(e));
                        if has_keyword && has_endpoint {
                            should_fire = true;
                        }
                    }
                }
            }

            if should_fire {
                for &plugin_name in rule.chain_plugins {
                    if fired_chains.insert(format!("{}::{}", f.core.id, plugin_name)) {
                        if let Some(plugin) = plugins.iter().find(|p| p.name() == plugin_name) {
                            if !layer_policy.needs_approval(plugin.metadata().layer) || approval_gate.is_approved(plugin.name()).await {
                                debug!("🔱 REACTIVE ENGINE: Triggering {} for finding {} on {}", plugin_name, f.core.id, target.host);
                                if let Ok(mut chain_findings) = plugin.scan(&reactive_snapshot).await {
                                    extra_findings.append(&mut chain_findings);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    extra_findings
}
