use sqlx::PgPool;
use tokio::sync::OnceCell;
use serde::{Serialize, Deserialize};
use tracing::{info, warn};

static MANAGER: OnceCell<CveCacheManager> = OnceCell::const_new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMetadata {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub severity: String,
    pub tactical_path: Option<String>,
    pub references: Vec<String>,
}

pub struct CveCacheManager {
    pool: PgPool,
}

impl CveCacheManager {
    pub fn init(pool: PgPool) {
        let _ = MANAGER.set(CveCacheManager { pool });
    }

    pub fn global() -> Option<&'static CveCacheManager> {
        MANAGER.get()
    }

    /// Retrieves CVE metadata from the local SQLite cache.
    pub async fn get_cve(&self, cve_id: &str) -> anyhow::Result<Option<CveMetadata>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT json_data::text FROM cve_cache WHERE cve_id = $1"
        )
        .bind(cve_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((json,)) = row {
            let metadata: CveMetadata = serde_json::from_str(&json)?;
            return Ok(Some(metadata));
        }

        Ok(None)
    }

    /// Fetches CVE metadata from NVD API v2 if not in local cache, then saves it.
    /// Rate limit: 5 req/30s anonymous, 50 req/30s with API key (NVD_API_KEY env var).
    pub async fn get_or_fetch_cve(&self, cve_id: &str) -> anyhow::Result<Option<CveMetadata>> {
        // Cache hit — return immediately
        if let Some(cached) = self.get_cve(cve_id).await? {
            return Ok(Some(cached));
        }

        // Cache miss — fetch from NVD API v2
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
        let mut req = reqwest::Client::new().get(&url)
            .header("User-Agent", "Mimikri/14.2 (security-research)");

        if let Ok(key) = std::env::var("NVD_API_KEY") {
            req = req.header("apiKey", key);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("V14.2 CVE-FETCH: NVD request failed for {}: {}", cve_id, e);
                return Ok(None);
            }
        };

        if !resp.status().is_success() {
            warn!("V14.2 CVE-FETCH: NVD returned {} for {}", resp.status(), cve_id);
            return Ok(None);
        }

        let body: serde_json::Value = resp.json().await?;

        let vuln = match body.pointer("/vulnerabilities/0/cve") {
            Some(v) => v,
            None => return Ok(None),
        };

        let description = vuln
            .pointer("/descriptions")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.iter().find(|e| e.get("lang").and_then(|l| l.as_str()) == Some("en")))
            .and_then(|e| e.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("No description available")
            .to_string();

        // Try CVSS v3.1 first, fall back to v3.0, then v2
        let cvss_score = vuln
            .pointer("/metrics/cvssMetricV31/0/cvssData/baseScore")
            .or_else(|| vuln.pointer("/metrics/cvssMetricV30/0/cvssData/baseScore"))
            .or_else(|| vuln.pointer("/metrics/cvssMetricV2/0/cvssData/baseScore"))
            .and_then(|v| v.as_f64())
            .map(|s| s as f32);

        let severity = vuln
            .pointer("/metrics/cvssMetricV31/0/cvssData/baseSeverity")
            .or_else(|| vuln.pointer("/metrics/cvssMetricV30/0/cvssData/baseSeverity"))
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        let references: Vec<String> = vuln
            .pointer("/references")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter()
                .filter_map(|e| e.get("url").and_then(|u| u.as_str()).map(String::from))
                .take(5) // Cap at 5 references to keep reports clean
                .collect())
            .unwrap_or_default();

        let metadata = CveMetadata {
            cve_id: cve_id.to_string(),
            description,
            cvss_score,
            severity,
            tactical_path: None, // NVD doesn't provide exploit paths
            references,
        };

        self.save_cve(&metadata).await?;
        info!("🌐 V14.2 CVE-FETCH: Fetched and cached {} from NVD", cve_id);
        Ok(Some(metadata))
    }

    /// Saves CVE metadata to the local SQLite cache.
    pub async fn save_cve(&self, metadata: &CveMetadata) -> anyhow::Result<()> {
        let json = serde_json::to_string(metadata)?;
        
        sqlx::query(
            "INSERT INTO cve_cache (cve_id, json_data, last_updated) VALUES ($1, $2::jsonb, CURRENT_TIMESTAMP) ON CONFLICT(cve_id) DO UPDATE SET json_data = EXCLUDED.json_data, last_updated = EXCLUDED.last_updated"
        )
        .bind(&metadata.cve_id)
        .bind(json)
        .execute(&self.pool)
        .await?;

        info!("💾 V14.2 CVE-CACHE: Cached metadata for {}", metadata.cve_id);
        Ok(())
    }
}
