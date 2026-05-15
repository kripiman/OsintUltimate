use dashmap::DashMap;
use once_cell::sync::Lazy;
use sha2::{Sha256, Digest};
use crate::models::Finding;
use sqlx::PgPool;
use tokio::sync::OnceCell;
use tracing::{info, error};

/// V14.2 Local Deduplication: in-memory session cache using SHA-256 identity hashes.
/// Key: SHA256(finding.id + matched_at), Value: first_seen timestamp
pub struct DeduplicationEngine {
    seen_hashes: DashMap<[u8; 32], i64>,
    pool: OnceCell<PgPool>,
}

static ENGINE: Lazy<DeduplicationEngine> = Lazy::new(DeduplicationEngine::new);

impl Default for DeduplicationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DeduplicationEngine {
    pub fn new() -> Self {
        Self { 
            seen_hashes: DashMap::new(),
            pool: OnceCell::new(),
        }
    }

    /// Initializes the engine with a persistent SQLite pool and loads existing hashes.
    pub async fn init(pool: PgPool) -> anyhow::Result<()> {
        let engine = &*ENGINE;
        
        // Load existing hashes from DB
        let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT finding_hash, first_seen FROM deduplication"
        )
        .fetch_all(&pool)
        .await?;

        info!("🛡️ V14.2 DEDUPE: Loading {} persistent hashes from SQLite", rows.len());

        for (hash_vec, first_seen) in rows {
            if let Ok(hash) = hash_vec.try_into() {
                engine.seen_hashes.insert(hash, first_seen);
            }
        }

        let _ = engine.pool.set(pool);
        Ok(())
    }

    /// Returns true if this finding was already seen this session or recorded in DB.
    /// MUST be called from within a Tokio async context (uses tokio::spawn internally).
    pub fn is_duplicate(finding: &Finding) -> bool {
        let matched_at = finding.evidence.primary.as_ref()
            .and_then(|e| e.data.get("matched_at"))
            .map(|v| v.to_string())
            .unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(finding.core.id.as_bytes());
        hasher.update(matched_at.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        if ENGINE.seen_hashes.contains_key(&hash) {
            return true;
        }

        let now = chrono::Utc::now().timestamp();
        ENGINE.seen_hashes.insert(hash, now);

        // Persistent sync (Fire-and-forget background task)
        if let Some(pool) = ENGINE.pool.get() {
            let pool = pool.clone();
            tokio::spawn(async move {
                let res = sqlx::query(
                    "INSERT INTO deduplication (finding_hash, first_seen) VALUES ($1, $2) ON CONFLICT(finding_hash) DO NOTHING"
                )
                .bind(hash.to_vec())
                .bind(now)
                .execute(&pool)
                .await;

                if let Err(e) = res {
                    error!("❌ V14.2 DEDUPE: Failed to persist hash to SQLite: {}", e);
                }
            });
        }

        false
    }

    pub fn global() -> &'static DeduplicationEngine {
        &ENGINE
    }
}
