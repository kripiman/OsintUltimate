use sqlx::{PgPool, Row};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Sha256, Digest};
use std::time::Duration;
use tracing::{info, debug};
use chrono::{Utc, DateTime};

use std::sync::OnceLock;

pub struct ApiCache {
    pool: PgPool,
}

static CACHE: OnceLock<ApiCache> = OnceLock::new();

impl ApiCache {
    pub fn init(pool: PgPool) {
        let cache = Self { pool };
        let _ = CACHE.set(cache);
    }

    pub fn global() -> Option<&'static Self> {
        CACHE.get()
    }

    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn generate_key(api: &str, target: &str, kind: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(api.as_bytes());
        hasher.update(b":");
        hasher.update(target.as_bytes());
        hasher.update(b":");
        hasher.update(kind.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn get<T: DeserializeOwned>(&self, api: &str, target: &str, kind: &str, ttl: Duration) -> Option<T> {
        let key = Self::generate_key(api, target, kind);
        
        match sqlx::query("SELECT output, timestamp FROM plugin_cache WHERE cache_key = $1")
            .bind(&key)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(row)) => {
                let timestamp: DateTime<Utc> = row.get("timestamp");
                let now = Utc::now();
                let age = now.signed_duration_since(timestamp);
                
                if age.num_seconds() > 0 && age.num_seconds() as u64 <= ttl.as_secs() {
                    let output: String = row.get("output");
                    match serde_json::from_str(&output) {
                        Ok(data) => {
                            info!("🚀 [API-CACHE] Hit for {} on {} ({})", api, target, kind);
                            Some(data)
                        }
                        Err(e) => {
                            debug!("Failed to deserialize cache for {}: {}", key, e);
                            None
                        }
                    }
                } else {
                    debug!("Cache expired for {}", key);
                    None
                }
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Database error fetching cache {}: {}", key, e);
                None
            }
        }
    }

    pub async fn put<T: Serialize>(&self, api: &str, target: &str, kind: &str, value: &T) {
        let key = Self::generate_key(api, target, kind);
        
        match serde_json::to_string(value) {
            Ok(output) => {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO plugin_cache (cache_key, output, timestamp) 
                    VALUES ($1, $2, CURRENT_TIMESTAMP)
                    ON CONFLICT (cache_key) DO UPDATE 
                    SET output = EXCLUDED.output, timestamp = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&key)
                .bind(&output)
                .execute(&self.pool)
                .await;
            }
            Err(e) => debug!("Failed to serialize value for cache {}: {}", key, e),
        }
    }
}
