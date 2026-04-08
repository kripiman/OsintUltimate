use std::time::Duration;
use reqwest::Client;
use tracing::info;

/// Detects if the current process is running within Oracle Cloud (OCI).
/// Uses the OCI instance metadata service (IMDS) v2.
pub async fn is_oracle_cloud() -> bool {
    let client = Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap_or_default();

    // Oracle Cloud Metadata Service endpoint
    let url = "http://169.254.169.254/opc/v2/instance/";
    
    match client.get(url)
        .header("Authorization", "Bearer Oracle")
        .send()
        .await
    {
        Ok(res) => {
            if res.status().is_success() {
                info!("🔍 STEALTH: Oracle Cloud (OCI) detected. Enforcing total proxy mode.");
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}
