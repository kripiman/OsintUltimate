use std::sync::Arc;
use tokio::sync::mpsc;
use bloomfilter::Bloom;
use crate::models::{TargetHost, TargetStatus, TargetType, Finding, Category, Severity};
use crate::plugins::DiscoveryPlugin;
use crate::utils::JitterSleep;

pub fn spawn_discovery_stage(
    rx: mpsc::Receiver<TargetHost>,
    liveness_tx: mpsc::Sender<TargetHost>,
    discovery_plugins: Arc<Vec<Box<dyn DiscoveryPlugin>>>,
    jitter: Option<JitterSleep>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let mut seen_domains = Bloom::new_for_fp_rate(1_000_000, 0.01);
    let mut rx = rx;

    tokio::spawn(async move {
        while let Some(mut target) = rx.recv().await {
            if shutdown_token.is_cancelled() { break; }

            if target.target_type == TargetType::Mobile || target.target_type == TargetType::Container {
                let _ = liveness_tx.send(target).await;
                continue;
            }
            
            if let Some(ref j) = jitter {
                j.apply().await;
            }

            if seen_domains.check(&target.host) { continue; }
            seen_domains.set(&target.host);

            let _ = liveness_tx.send(target.clone()).await;

            let mut join_set = tokio::task::JoinSet::new();
            for i in 0..discovery_plugins.len() {
                let plugins_clone = discovery_plugins.clone();
                let target_snapshot = target.clone();
                join_set.spawn(async move {
                    let plugin = &plugins_clone[i];
                    let name = plugin.name().to_string();
                    let result = plugin.discover(&target_snapshot).await;
                    (name, result)
                });
            }

            while let Some(join_res) = join_set.join_next().await {
                if let Ok((name, Ok(subdomains))) = join_res {
                    for res in subdomains {
                        if !seen_domains.check(&res.host) {
                            seen_domains.set(&res.host);
                            
                            let mut data = serde_json::json!({ "subdomain": res.host, "source": name });
                            if let Some(obj) = res.metadata.as_object() {
                                for (k, v) in obj {
                                    data[k] = v.clone();
                                }
                            }

                            let priority_plugins = res.metadata["priority_plugins"].clone();
                            let high_value = res.metadata["high_value_target"].clone();

                            Arc::make_mut(&mut target.findings).push(Finding::new(
                                "DISCOVERED_SUBDOMAIN", 
                                Category::Recon, 
                                Severity::Info, 
                                &format!("Discovered via {}: {}", name, res.host), 
                                data
                            ));
                            
                            let new_host = TargetHost { 
                                host: res.host.clone(), 
                                ip: None, 
                                resolved_ip: None,
                                status: TargetStatus::Pending, 
                                target_type: TargetType::Web,
                                file_path: None,
                                user: None,
                                findings: Arc::new(Vec::new()),
                                tool_suggestions: Arc::new(Vec::new()),
                                tactical_context: Arc::new(serde_json::json!({
                                    "priority_plugins": priority_plugins,
                                    "high_value_target": high_value,
                                })),
                                extra_data: Arc::new(serde_json::json!({})),
                                version: 0,
                                skip_heavy_scan: false,
                                scan_id: target.scan_id,
                                scope_id: String::new(),
                            };

                            let is_oracle = std::env::var("ORACLE_OVERRIDE").is_err() && 
                                          crate::utils::stealth_detect::is_oracle_cloud().await;
                            let mut pushed_to_db = false;

                            if is_oracle {
                                if let Ok(db_url) = std::env::var("DATABASE_URL") {
                                    if let Ok(pool) = sqlx::PgPool::connect(&db_url).await {
                                        let exists: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM scan_queue WHERE host = $1")
                                            .bind(&new_host.host)
                                            .fetch_optional(&pool)
                                            .await
                                            .ok()
                                            .flatten();
                                            
                                        if let Some((count,)) = exists {
                                            if count > 0 {
                                                // It's a duplicate. We don't insert, but we mark as pushed so it skips local scanning.
                                                pushed_to_db = true;
                                            } else {
                                                let res = sqlx::query(
                                                    "INSERT INTO scan_queue (host, target_type, tactical_context, priority, status, worker_profile) VALUES ($1, $2, $3, $4, 'pending', 'scan')"
                                                )
                                                .bind(&new_host.host)
                                                .bind(format!("{:?}", new_host.target_type))
                                                .bind(&*new_host.tactical_context)
                                                .bind(1i32)
                                                .execute(&pool)
                                                .await;
                                                
                                                if res.is_ok() {
                                                    tracing::info!("📦 [OSINT-DB] Enqueued discovered subdomain to DB for DO Swarm: {}", new_host.host);
                                                    pushed_to_db = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if !pushed_to_db {
                                let _ = liveness_tx.send(new_host).await;
                            }
                        }
                    }
                }
            }
            let _ = liveness_tx.send(target).await;
        }
    })
}
