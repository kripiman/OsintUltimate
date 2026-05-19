use crate::models::{Finding, TargetHost};
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayerPolicy;
use crate::core::approval_gate::ApprovalGate;
use dashmap::DashSet;
use std::sync::Arc;
use tracing::{debug, info};
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
    StartsWith(&'static str),
}

impl RuleTrigger {
    pub fn matches(&self, finding_id: &str) -> bool {
        match self {
            RuleTrigger::Single(id) => *id == finding_id,
            RuleTrigger::AnyOf(ids) => ids.contains(&finding_id),
            RuleTrigger::StartsWith(prefix) => finding_id.starts_with(prefix),
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
    // 3. GraphQL -> GraphW00f/Schemathesis/CrackQL/Clairvoyance
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_GRAPHQL_INTROSPECTION),
        chain_plugins: &[PLUGIN_CLAIRVOYANCE, PLUGIN_GRAPHW00F, PLUGIN_SCHEMATHESIS, PLUGIN_CRACKQL],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "api_url" } 
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
    // 11. AD Reactive Triggers (I8)
    ReactiveRule {
        trigger: RuleTrigger::StartsWith("PORT:389"), // LDAP
        chain_plugins: &[PLUGIN_BLOODHOUND],
        extractor: ContextExtractor::PassThrough
    },
    ReactiveRule {
        trigger: RuleTrigger::StartsWith("PORT:445"), // SMB
        chain_plugins: &[PLUGIN_NETEXEC],
        extractor: ContextExtractor::PassThrough
    },
    ReactiveRule {
        trigger: RuleTrigger::StartsWith("PORT:139"), // NetBIOS
        chain_plugins: &[PLUGIN_RESPONDER],
        extractor: ContextExtractor::PassThrough
    },
    // 12. SMB Relay / Spray Chain (Phase 5.3)
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_SMB_SIGNING_DISABLED),
        chain_plugins: &[PLUGIN_NETEXEC],
        extractor: ContextExtractor::PassThrough // Inventory will provide credentials
    },
    // 13. NTLM Hash -> NetExec (Immediate Trigger)
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_NTLM_HASH_CAPTURED),
        chain_plugins: &[PLUGIN_NETEXEC],
        extractor: ContextExtractor::PassThrough,
    },
    // 14. SMB Pwned! -> Sliver Implant Delivery
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_SMB_PWNED),
        chain_plugins: &[PLUGIN_SLIVER_AUTOMATOR],
        extractor: ContextExtractor::PassThrough,
    },
    // 15. Attack Path Found -> Final Lateral Movement (Phase 6)
    ReactiveRule {
        trigger: RuleTrigger::StartsWith(FINDING_ATTACK_PATH),
        chain_plugins: &[PLUGIN_NETEXEC],
        extractor: ContextExtractor::EvidenceField { source_key: "host", target_key: "host" },
    },
    // 16. JWKS -> JWT Forge
    ReactiveRule { 
        trigger: RuleTrigger::Single(FINDING_JWKS_ENDPOINT), 
        chain_plugins: &[PLUGIN_JWT_FORGE],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "jwks_url" } 
    },
    // 17. CORS Misconfig -> Exfiltrator
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_CORS_MISCONFIG),
        chain_plugins: &[PLUGIN_CORS_EXFIL],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "api_url" }
    },
    // 18. Subdomain Takeover -> Verifier
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_SUBDOMAIN_TAKEOVER),
        chain_plugins: &[PLUGIN_DNS_VERIFIER],
        extractor: ContextExtractor::PassThrough
    },
    // 19. Exposed Secret -> Validator
    ReactiveRule {
        trigger: RuleTrigger::AnyOf(&[FINDING_GITLEAKS_SECRET, FINDING_EXPOSED_SECRET, FINDING_JS_SECRET]),
        chain_plugins: &[PLUGIN_SECRET_VALIDATOR],
        extractor: ContextExtractor::EvidenceField { source_key: "secret", target_key: "secret" }
    },
    // 20. SSRF -> AWS IMDSv2 Bypass
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_SSRF),
        chain_plugins: &[PLUGIN_IMDS_BYPASS],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "url" }
    },
    // 21. GraphQL Introspection -> Exploiter
    ReactiveRule {
        trigger: RuleTrigger::Single(FINDING_GRAPHQL_INTROSPECTION),
        chain_plugins: &[PLUGIN_GRAPHQL_EXPLOITER],
        extractor: ContextExtractor::EvidenceField { source_key: "url", target_key: "graphql_endpoint" }
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
    #[allow(unused_mut)]
    let mut rules = BASE_RULES.to_vec();
    #[cfg(feature = "sovereign")]
    {
        rules.extend_from_slice(SOVEREIGN_RULES);
    }
    rules
}

pub struct ReactiveContext<'a> {
    pub findings: &'a [Finding],
    pub target: &'a TargetHost,
    pub plugins: &'a [Box<dyn ScannerPlugin>],
    pub layer_policy: &'a ScanLayerPolicy,
    pub approval_gate: &'a ApprovalGate,
    pub fired_chains: &'a DashSet<String>,
    pub inventory: Option<&'a crate::core::orchestrator::swarm::inventory::SwarmInventory>,
}

pub struct ReactiveEngine {
    rules: Vec<ReactiveRule>,
}

impl Default for ReactiveEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReactiveEngine {
    pub fn new() -> Self {
        Self {
            rules: get_all_rules(),
        }
    }

    pub async fn evaluate(
        &self,
        ctx: ReactiveContext<'_>,
    ) -> Vec<Finding> {
        evaluate(&self.rules, ctx).await
    }
}

pub async fn evaluate(
    rules: &[ReactiveRule],
    ctx: ReactiveContext<'_>,
) -> Vec<Finding> {
    let mut extra_findings = Vec::new();

    for rule in rules {
        // Find if any existing finding matches the trigger
        let trigger_findings: Vec<&Finding> = ctx.findings.iter()
            .filter(|f| {
                // V17 HARDENING: Enforce Scope Isolation (I5)
                if f.core.scope_id != ctx.target.scope_id {
                    return false;
                }
                rule.trigger.matches(&f.core.id)
            })
            .collect();

        for f in trigger_findings {
            // V15.1: Enforce Reactive Chain Depth Limit (Safety Gate)
            let chain_depth = f.core.reactive_depth;
                
            if chain_depth >= 5 {
                tracing::warn!("🔱 REACTIVE ENGINE: Chain depth limit (5) reached for finding {}. Aborting chain.", f.core.id);
                continue;
            }

            // Apply extractor and check if we should fire
            let mut reactive_snapshot = ctx.target.clone();
            let mut should_fire = false;

            match &rule.extractor {
                ContextExtractor::EvidenceField { source_key, target_key } => {
                    if let Some(val) = f.evidence.primary.as_ref()
                        .and_then(|e| e.data.get(*source_key))
                        .cloned() 
                    {
                        if target_key == &"host" {
                            if let Some(host_str) = val.as_str() {
                                reactive_snapshot.host = host_str.to_string();
                                info!("🔱 REACTIVE PIVOT: Target host updated to {} based on finding evidence.", reactive_snapshot.host);
                            }
                        }
                        
                        Arc::make_mut(&mut reactive_snapshot.extra_data)
                            .as_object_mut()
                            .and_then(|obj| obj.insert(target_key.to_string(), val));
                        should_fire = true;
                    }
                }
                ContextExtractor::EvidenceArray { source_key, target_key } => {
                    if let Some(params) = f.evidence.primary.as_ref()
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
                    if let Some(evidence) = f.evidence.primary.as_ref() {
                        let content = evidence.data.to_string().to_lowercase();
                        if keywords.iter().any(|&k| content.contains(k)) {
                            should_fire = true;
                        }
                    }
                }
                ContextExtractor::RegexMatch { pattern } => {
                    if let Some(re) = COMPILED_REGEXES.get(*pattern) {
                        if let Some(evidence) = f.evidence.primary.as_ref() {
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
                    if let Some(evidence) = f.evidence.primary.as_ref() {
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
                    if ctx.fired_chains.insert(format!("{}::{}", f.core.id, plugin_name)) {
                        if let Some(plugin) = ctx.plugins.iter().find(|p| p.name() == plugin_name) {
                            if !ctx.layer_policy.needs_approval(plugin.metadata().layer) || ctx.approval_gate.is_approved(plugin.name()).await {
                                debug!("🔱 REACTIVE ENGINE: Triggering {} for finding {} on {}", plugin_name, f.core.id, ctx.target.host);
                                if let Ok(mut chain_findings) = plugin.scan(&reactive_snapshot).await {
                                    // V15.1: Propagate and increment chain depth
                                    for cf in &mut chain_findings {
                                        cf.core.reactive_depth = chain_depth + 1;
                                    }
                                    extra_findings.append(&mut chain_findings);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // --- PHASE 5.2: CROSS-TARGET CREDENTIAL SPRAYING ---
    if let Some(inv) = ctx.inventory {
        let auth_scanners: Vec<&Box<dyn ScannerPlugin>> = ctx.plugins.iter()
            .filter(|p| p.metadata().capabilities.contains(&crate::plugins::Capability::BruteForce))
            .collect();
            
        if !auth_scanners.is_empty() {
             let authorized_creds = inv.get_authorized_credentials(&ctx.target.scope_id);
             for cred in authorized_creds {
                  for p in &auth_scanners {
                      if ctx.fired_chains.insert(format!("SPRAY:{}::{}::{}", cred.core.id, p.name(), ctx.target.host)) {
                          debug!("🔱 SWARM INVENTORY: Spraying credential {} using {} on {}", cred.core.id, p.name(), ctx.target.host);
                          
                          let mut reactive_snapshot = ctx.target.clone();
                           // Inject credential into tactical context
                           let obj = Arc::make_mut(&mut reactive_snapshot.extra_data).as_object_mut();
                           if let Some(o) = obj {
                               o.insert("injected_credential".into(), serde_json::json!(cred));
                               
                               // Also inject flat keys for direct access
                               if let Some(evidence) = cred.evidence.primary.as_ref() {
                                   if let Some(u) = evidence.data.get("username").or_else(|| evidence.data.get("user")) {
                                       o.insert("username".into(), u.clone());
                                   }
                                   if let Some(h) = evidence.data.get("hash").or_else(|| evidence.data.get("ntlm")) {
                                       o.insert("ntlm_hash".into(), h.clone());
                                   }
                                   if let Some(p) = evidence.data.get("password").or_else(|| evidence.data.get("pass")) {
                                       o.insert("password".into(), p.clone());
                                   }
                               }
                           }

                          if let Ok(mut spray_findings) = p.scan(&reactive_snapshot).await {
                              extra_findings.append(&mut spray_findings);
                          }
                      }
                  }
             }
        }
    }

    extra_findings
}
