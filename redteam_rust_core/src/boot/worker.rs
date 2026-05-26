use crate::boot::cli::Args;
use redteam_rust_core::models::{TargetHost, TargetStatus};
use redteam_rust_core::models::worker_profile::WorkerProfile;
use redteam_rust_core::core::engine::{RedTeamEngine, app::EngineConfig};
use redteam_rust_core::core::sink::{MultiSink, PostgresSink, DataSink};
use redteam_rust_core::core::capability_layer::ScanLayer;
use redteam_rust_core::core::verification::interaction::OobInteractionManager;
use redteam_rust_core::utils::config::Config;
use redteam_rust_core::models::ScanMetadata;
use async_trait::async_trait;
use tracing::{info, error};
use anyhow::{Result, Context};
use std::time::Duration;
use std::str::FromStr;
use std::sync::Arc;

/// Wrapper sink that injects oob_correlation_id into every Finding's context
/// before passing to the inner sink. Centralized injection — no plugin changes needed.
pub struct OobEnrichingSink {
    inner: Box<dyn DataSink>,
    oob_id: String,
}

impl OobEnrichingSink {
    pub fn new(inner: Box<dyn DataSink>, oob_id: String) -> Self {
        Self { inner, oob_id }
    }
}

#[async_trait]
impl DataSink for OobEnrichingSink {
    async fn write(&mut self, target: &TargetHost) -> Result<()> {
        let mut enriched = target.clone();
        let findings: Vec<_> = target.findings.iter().map(|f| {
            let mut finding = f.clone();
            finding.context.oob_correlation_id = Some(self.oob_id.clone());
            finding
        }).collect();
        enriched.findings = Arc::new(findings);
        self.inner.write(&enriched).await
    }

    async fn write_metadata(&mut self, metadata: &ScanMetadata) -> Result<()> {
        self.inner.write_metadata(metadata).await
    }

    async fn close(&mut self) -> Result<()> {
        self.inner.close().await
    }

    fn get_db_pool(&self) -> Option<sqlx::PgPool> {
        self.inner.get_db_pool()
    }

    fn get_scan_id(&self) -> Option<i64> {
        self.inner.get_scan_id()
    }
}

pub fn resolve_worker_profile(args: &Args) -> WorkerProfile {
    if args.cve_correlation_only {
        WorkerProfile::CveCorrelation
    } else {
        WorkerProfile::from_str(&args.profile).unwrap_or_default()
    }
}

pub fn resolve_max_layer(profile: WorkerProfile, cli_layer: &str) -> ScanLayer {
    match profile {
        WorkerProfile::Scan => ScanLayer::from_str(cli_layer).unwrap_or(ScanLayer::Scanning),
        WorkerProfile::Enrich | WorkerProfile::CveCorrelation => ScanLayer::Passive,
    }
}

pub async fn run_worker_mode(args: &Args) -> Result<()> {
    let cli_scope_id = Arc::new(args.scope_id.clone().unwrap_or_default());
    let db_url = args.postgres_url.as_ref().context("Postgres URL is required for worker mode (--postgres-url)")?;
    let node_id = args.node_id.clone().unwrap_or_else(|| {
        format!("node-{}", std::process::id())
    });

    let profile = resolve_worker_profile(args);
    info!("🐝 [Worker] Starting in distributed mode. Node ID: {} | Profile: {}", node_id, profile);
    let pool = sqlx::PgPool::connect(db_url).await?;

    // Register node
    sqlx::query("INSERT INTO workers (id, status) VALUES ($1, 'active') ON CONFLICT(id) DO UPDATE SET last_seen = NOW(), status = 'active'")
        .bind(&node_id)
        .execute(&pool)
        .await?;

    let utils_config = Arc::new(Config::from_env());

    // Initialize global singletons once per worker node
    redteam_rust_core::utils::api_budget::ApiBudgetRegistry::init(&utils_config, Some(pool.clone()));
    redteam_rust_core::utils::api_cache::ApiCache::init(pool.clone());
    redteam_rust_core::utils::shodan_keyring::ShodanKeyring::init(&utils_config);
    info!("🛡️ [Worker] ApiBudgetRegistry initialized (DB-backed).");
    info!("🛡️ [Worker] ApiCache initialized (DB-backed).");
    info!("🛡️ [Worker] ShodanKeyring initialized.");
    
    let semaphore = Arc::new(tokio::sync::Semaphore::new(args.concurrency.max(1)));
    
    loop {
        // Wait until we have a permit before pulling a job.
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        // Poll for a job matching this worker's profile
        let job: Option<(i32, String, String, serde_json::Value)> = sqlx::query_as(
            "UPDATE scan_queue SET status = 'claimed', claimed_by = $1, updated_at = NOW()
             WHERE id = (
                 SELECT id FROM scan_queue
                 WHERE status = 'pending' AND worker_profile = $2
                 ORDER BY priority DESC, created_at ASC
                 LIMIT 1 FOR UPDATE SKIP LOCKED
             ) RETURNING id, host, target_type, tactical_context"
        )
        .bind(&node_id)
        .bind(profile.to_string())
        .fetch_optional(&pool)
        .await?;

        if let Some((id, host, target_type, tactical_context)) = job {
            info!("📦 [Worker] Claimed job {}: {} ({})", id, host, target_type);
            
            let pool_clone = pool.clone();
            let _node_id_clone = node_id.clone();
            let args_clone = args.clone();
            let utils_config_clone = utils_config.clone();
            let cli_scope_id_clone = cli_scope_id.clone();
            let db_url_clone = db_url.clone();

            tokio::spawn(async move {
                let _permit = permit; // Keep permit alive until task finishes
                
                // Re-use engine setup logic from main
                let engine_config = EngineConfig {
                    concurrency: args_clone.concurrency,
                    insecure: args_clone.insecure,
                    stealth: args_clone.stealth,
                    service_detection: args_clone.service_detection,
                    scan_type: args_clone.scan_type.clone(),
                    fragment: args_clone.fragment,
                    decoy: args_clone.decoy.clone(),
                    ports: args_clone.ports.clone(),
                    vuln_scan: args_clone.vuln_scan,
                    max_tokens: args_clone.max_tokens,
                    ollama_url: utils_config_clone.ollama_url.clone(),
                    policy_file: utils_config_clone.policy_file.clone(),
                    strict_scope: utils_config_clone.strict_scope,
                    nuclei_auto_update: utils_config_clone.nuclei_auto_update,
                    h1_username: utils_config_clone.h1_username.clone(),
                    h1_api_key: utils_config_clone.h1_api_key.clone(),
                    bugcrowd_api_key: utils_config_clone.bugcrowd_api_key.clone(),
                    intigriti_token: utils_config_clone.intigriti_token.clone(),
                    bb_program_handle: utils_config_clone.bb_program_handle.clone(),
                    scripts: args_clone.scripts.clone(),
                    dns_servers: args_clone.dns_servers.as_ref().map(|s| s.split(',').map(|i| i.trim().to_string()).collect()),
                    doh: args_clone.doh,
                    proxies: args_clone.proxies.as_ref().map(|s| s.split(',').map(|i| i.trim().to_string()).collect()),
                    plugins_dir: args_clone.plugins_dir.clone(),
                    max_layer: resolve_max_layer(profile, &args_clone.max_layer),
                    dashboard_port: args_clone.dashboard,
                    readiness_timeout: std::time::Duration::from_secs(60),
                    proxy_mode: utils_config_clone.proxy_mode,
                    proxy_pool_size: utils_config_clone.proxy_pool_size,
                    mcp_token: utils_config_clone.mcp_token.clone(),
                    mobsf_url: utils_config_clone.mobsf_url.clone(),
                    mobsf_api_key: utils_config_clone.mobsf_api_key.clone(),
                    mobsf_timeout_secs: utils_config_clone.mobsf_timeout_secs,
                    vigil_url: utils_config_clone.vigil_url.clone(),
                    vigil_api_key: utils_config_clone.vigil_api_key.clone(),
                    rebuff_url: utils_config_clone.rebuff_url.clone(),
                    rebuff_api_token: utils_config_clone.rebuff_api_token.clone(),
                    dashboard_tx: None,
                    dashboard_targets: None,
                    clairvoyance_wordlist_path: utils_config_clone.clairvoyance_wordlist_path.clone(),
                    shuffledns_resolvers_path: utils_config_clone.shuffledns_resolvers_path.clone(),
                    shuffledns_wordlist_path: utils_config_clone.shuffledns_wordlist_path.clone(),
                    ssrfmap_path: utils_config_clone.ssrfmap_path.clone(),
                    nosqlmap_path: utils_config_clone.nosqlmap_path.clone(),
                    ghauri_path: utils_config_clone.ghauri_path.clone(),
                    gopherus_path: utils_config_clone.gopherus_path.clone(),
                    kxss_path: utils_config_clone.kxss_path.clone(),
                    s3scanner_path: utils_config_clone.s3scanner_path.clone(),
                    s3scanner_wordlist_path: utils_config_clone.s3scanner_wordlist_path.clone(),
                    shuffledns_path: utils_config_clone.shuffledns_path.clone(),
                    massdns_path: utils_config_clone.massdns_path.clone(),
                    sliver_ca_path: utils_config_clone.sliver_ca_path.clone(),
                    sliver_cert_path: utils_config_clone.sliver_cert_path.clone(),
                    sliver_key_path: utils_config_clone.sliver_key_path.clone(),
                    sliver_server_addr: utils_config_clone.sliver_server_addr.clone(),
                    workspace_dir: utils_config_clone.workspace_dir.clone(),
                };

                let engine = RedTeamEngine::from_config(engine_config, &utils_config_clone);

                // Sprint 10: Deterministic OOB correlation ID per queue job
                let oob_id = OobInteractionManager::generate_id_for_queue(id.into());
                let mut tactical_context = tactical_context;
                if let Some(obj) = tactical_context.as_object_mut() {
                    obj.insert("oob_correlation_id".to_string(), serde_json::json!(oob_id));
                } else {
                    tactical_context = serde_json::json!({"oob_correlation_id": oob_id});
                }
                
                let target = TargetHost {
                    host: host.clone(),
                    ip: None,
                    resolved_ip: None,
                    status: TargetStatus::Pending,
                    target_type: serde_json::from_str(&format!("\"{}\"", target_type)).unwrap_or(redteam_rust_core::models::TargetType::Web),
                    file_path: None,
                    user: None,
                    findings: Arc::new(Vec::new()),
                    tool_suggestions: Arc::new(Vec::new()),
                    tactical_context: Arc::new(tactical_context),
                    extra_data: Arc::new(serde_json::json!({})),
                    version: 0,
                    skip_heavy_scan: false,
                    scan_id: None, 
                    scope_id: (*cli_scope_id_clone).clone(),
                };

                let mut multi_sink = MultiSink::new();
                let postgres_init = PostgresSink::new(db_url_clone).await;
                match postgres_init {
                    Ok(ps) => {
                        multi_sink.add(Box::new(ps));
                        
                        // Add BountySink if credentials present
                        if utils_config_clone.h1_api_key.is_some() || utils_config_clone.bugcrowd_api_key.is_some() || utils_config_clone.intigriti_token.is_some() {
                            multi_sink.add(Box::new(redteam_rust_core::core::sink::BountySink::new(
                                utils_config_clone.h1_username.clone(),
                                utils_config_clone.h1_api_key.clone(),
                                utils_config_clone.bugcrowd_api_key.clone(),
                                utils_config_clone.intigriti_token.clone(),
                                utils_config_clone.bb_program_handle.clone(),
                            )));
                        }

                        let oob_sink = OobEnrichingSink::new(Box::new(multi_sink), oob_id);
                        let target_stream = Box::pin(futures::stream::once(async move { target }));
                        match engine.run_autopilot(target_stream, Box::new(oob_sink)).await {
                            Ok(_) => {
                                info!("✅ [Worker] Completed job {}", id);
                                let _ = sqlx::query("UPDATE scan_queue SET status = 'completed', updated_at = NOW() WHERE id = $1")
                                    .bind(id)
                                    .execute(&pool_clone)
                                    .await;
                            },
                            Err(e) => {
                                error!("❌ [Worker] Job {} failed: {}", id, e);
                                let _ = sqlx::query("UPDATE scan_queue SET status = 'failed', updated_at = NOW() WHERE id = $1")
                                    .bind(id)
                                    .execute(&pool_clone)
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ [Worker] Job {} failed to initialize PostgresSink: {}", id, e);
                        let _ = sqlx::query("UPDATE scan_queue SET status = 'failed', updated_at = NOW() WHERE id = $1")
                            .bind(id)
                            .execute(&pool_clone)
                            .await;
                    }
                }
            });
        } else {
            // Release permit if no job was found
            drop(permit);
            
            // No jobs, sleep
            tokio::time::sleep(Duration::from_secs(5)).await;
            
            // Keep-alive for worker node
            let _ = sqlx::query("UPDATE workers SET last_seen = NOW() WHERE id = $1")
                .bind(&node_id)
                .execute(&pool)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redteam_rust_core::models::worker_profile::WorkerProfile;
    use redteam_rust_core::models::{Finding, Category, Severity};
    use redteam_rust_core::core::sink::DataSink;
    use async_trait::async_trait;

    /// Mock sink that captures all TargetHosts written for test inspection.
    struct MockSink {
        pub targets: std::sync::Arc<std::sync::Mutex<Vec<TargetHost>>>,
    }

    #[async_trait]
    impl DataSink for MockSink {
        async fn write(&mut self, target: &TargetHost) -> Result<()> {
            self.targets.lock().unwrap().push(target.clone());
            Ok(())
        }
        async fn write_metadata(&mut self, _metadata: &ScanMetadata) -> Result<()> { Ok(()) }
        async fn close(&mut self) -> Result<()> { Ok(()) }
    }

    #[tokio::test]
    async fn test_oob_enriching_sink_injects_id() {
        let oob_id = "aabbccdd11223344".to_string();
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inner = Box::new(MockSink { targets: shared.clone() });
        let mut sink = OobEnrichingSink::new(inner, oob_id.clone());

        let finding = Finding::new(
            "TEST-FINDING",
            Category::Recon,
            Severity::Info,
            "test",
            serde_json::json!({})
        );
        let target = TargetHost {
            host: "example.com".to_string(),
            findings: Arc::new(vec![finding]),
            ..Default::default()
        };

        sink.write(&target).await.unwrap();

        let captured = shared.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].findings.len(), 1);
        assert_eq!(captured[0].findings[0].context.oob_correlation_id, Some(oob_id));
    }

    fn mock_args_with_profile(profile: &str) -> Args {
        Args {
            profile: profile.to_string(),
            cve_correlation_only: false,
            ..Default::default()
        }
    }

    fn mock_args_cve_only() -> Args {
        Args {
            profile: "scan".to_string(),
            cve_correlation_only: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_resolve_profile_scan() {
        let args = mock_args_with_profile("scan");
        assert_eq!(resolve_worker_profile(&args), WorkerProfile::Scan);
    }

    #[test]
    fn test_resolve_profile_enrich() {
        let args = mock_args_with_profile("enrich");
        assert_eq!(resolve_worker_profile(&args), WorkerProfile::Enrich);
    }

    #[test]
    fn test_resolve_profile_cve_correlation() {
        let args = mock_args_with_profile("cve_correlation");
        assert_eq!(resolve_worker_profile(&args), WorkerProfile::CveCorrelation);
    }

    #[test]
    fn test_resolve_profile_cve_alias() {
        let args = mock_args_cve_only();
        assert_eq!(resolve_worker_profile(&args), WorkerProfile::CveCorrelation);
    }

    #[test]
    fn test_resolve_max_layer_scan_uses_cli() {
        assert_eq!(resolve_max_layer(WorkerProfile::Scan, "Scanning"), ScanLayer::Scanning);
        assert_eq!(resolve_max_layer(WorkerProfile::Scan, "Passive"), ScanLayer::Passive);
    }

    #[test]
    fn test_resolve_max_layer_enrich_forces_passive() {
        assert_eq!(resolve_max_layer(WorkerProfile::Enrich, "Scanning"), ScanLayer::Passive);
        assert_eq!(resolve_max_layer(WorkerProfile::Enrich, "Discovery"), ScanLayer::Passive);
    }

    #[test]
    fn test_resolve_max_layer_cve_forces_passive() {
        assert_eq!(resolve_max_layer(WorkerProfile::CveCorrelation, "Scanning"), ScanLayer::Passive);
        assert_eq!(resolve_max_layer(WorkerProfile::CveCorrelation, "Exploitation"), ScanLayer::Passive);
    }
}
