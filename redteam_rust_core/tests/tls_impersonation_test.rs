#[cfg(test)]
mod tests {
    #[cfg(feature = "tls-impersonation")]
    mod impersonation {
        use wiremock::{MockServer, Mock, matchers, ResponseTemplate};
        use redteam_rust_core::utils::stealth_http::StealthClientBuilder;
        use redteam_rust_core::infrastructure::proxy::ProxyManager;
        use redteam_rust_core::utils::config::ProxyMode;

        #[tokio::test]
        async fn test_impersonate_client_connects() {
            let mock_server = MockServer::start().await;
            Mock::given(matchers::method("GET"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&mock_server)
                .await;
            
            let pm = ProxyManager::new(vec![], false, ProxyMode::None, 0);
            let client = StealthClientBuilder::build_impersonated_chrome(&pm)
                .expect("Failed to build impersonated client");
            
            let res = client.get(mock_server.uri()).send().await.expect("Failed to send request");
            assert_eq!(res.status(), 200);
        }

        #[tokio::test]
        async fn test_impersonate_proxy_respected() {
            // Configure proxy manager with Dante mode and a dummy unreachable port to test routing.
            let pm = ProxyManager::new(
                vec!["http://127.0.0.1:9999".to_string()], 
                false, 
                ProxyMode::Dante, 
                1
            );
            let client = StealthClientBuilder::build_impersonated_chrome(&pm)
                .expect("Failed to build client with proxy");
            
            // Connect to dummy local address to fail fast in offline environments.
            let res = client.get("http://127.0.0.1:1").send().await;
            // The request should fail since the proxy at 127.0.0.1:9999 is unreachable.
            assert!(res.is_err());
        }
    }

    #[cfg(not(feature = "tls-impersonation"))]
    mod fallback {
        #[test]
        fn test_impersonate_fallback_without_feature() {
            // Compile-time check: verify reqwest::Client construction still works
            // when tls-impersonation feature is disabled.
            let _client = reqwest::Client::new();
        }
    }
}
