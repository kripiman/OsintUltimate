/// DNS HTTPS RR fetcher for ECH configuration.
///
/// Automatically resolves ECHConfigList bytes from DNS HTTPS resource records
/// (RR type 65), making Sprint 7's `EchClient` usable without manual byte injection.
///
/// # Example
/// ```ignore
/// let fetcher = EchDnsFetcher::new().await?;
/// let ech_bytes = fetcher.fetch_ech_config("cloudflare-ech.com").await?;
/// let client = EchClient::with_ech_config(&ech_bytes)?;
/// ```
use anyhow::Result;

/// Fetches ECH configuration from DNS HTTPS records.
pub struct EchDnsFetcher {
    resolver: hickory_resolver::TokioAsyncResolver,
}

impl EchDnsFetcher {
    /// Create a fetcher using the system DNS configuration.
    pub async fn new() -> Result<Self> {
        let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| anyhow::anyhow!("resolver init failed: {e:?}"))?;
        Ok(Self { resolver })
    }

    /// Create a fetcher with a custom resolver (useful for testing).
    pub fn with_resolver(resolver: hickory_resolver::TokioAsyncResolver) -> Self {
        Self { resolver }
    }

    /// Query DNS for HTTPS records on `domain` and extract the first ECH config.
    ///
    /// Returns the raw ECHConfigList bytes suitable for `EchClient::with_ech_config()`.
    pub async fn fetch_ech_config(&self, domain: &str) -> Result<Vec<u8>> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

        let lookup = self
            .resolver
            .lookup(domain, RecordType::HTTPS)
            .await
            .map_err(|e| anyhow::anyhow!("DNS HTTPS lookup failed: {e:?}"))?;

        for record in lookup.record_iter() {
            if let Some(RData::HTTPS(https_rr)) = record.data() {
                for (key, value) in https_rr.svc_params() {
                    if *key == SvcParamKey::EchConfig {
                        if let SvcParamValue::EchConfig(ech) = value {
                            return Ok(ech.0.clone());
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "no ECH config found in HTTPS records for {domain}"
        ))
    }

    /// Convenience: fetch ECH config and immediately connect.
    ///
    /// `domain` is used both for DNS lookup and as the TLS server name.
    pub async fn fetch_and_connect(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<crate::core::net_evasion::ech_client::EchConnection> {
        let ech_bytes = self.fetch_ech_config(domain).await?;
        let client = crate::core::net_evasion::ech_client::EchClient::with_ech_config(&ech_bytes)?;
        client.connect(domain, port).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetcher_new() {
        let fetcher = EchDnsFetcher::new().await;
        assert!(
            fetcher.is_ok(),
            "EchDnsFetcher::new() should succeed: {:?}",
            fetcher.err()
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to real DNS resolvers"]
    async fn test_fetcher_with_cloudflare_ech() {
        let fetcher = EchDnsFetcher::new().await.unwrap();
        let result = fetcher.fetch_ech_config("cloudflare-ech.com").await;
        assert!(
            result.is_ok(),
            "cloudflare-ech.com should have ECH config: {:?}",
            result.err()
        );
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "ECH config should not be empty");
    }

    #[tokio::test]
    #[ignore = "requires network access to real DNS resolvers"]
    async fn test_fetcher_no_https_domain() {
        // Use a domain that is extremely unlikely to have HTTPS RRs.
        let fetcher = EchDnsFetcher::new().await.unwrap();
        let result = fetcher
            .fetch_ech_config("this-domain-should-not-exist-12345.invalid")
            .await;
        assert!(
            result.is_err(),
            "Non-existent domain should fail ECH fetch"
        );
    }

    #[test]
    fn test_fetcher_types() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EchDnsFetcher>();
    }
}
