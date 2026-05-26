use redteam_rust_core::core::verification::interaction::OobInteractionManager;
use redteam_rust_core::utils::proxy::ProxyManager;
use redteam_rust_core::utils::config::ProxyMode;
use std::sync::Arc;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, query_param};

/// E2E: OobInteractionManager polls a mocked interactsh-server and receives hits.
#[tokio::test]
async fn test_oob_poll_hits_against_mock_server() {
    let server = MockServer::start().await;

    let oob_id = "aabbccdd11223344";
    Mock::given(method("GET"))
        .and(path("/poll"))
        .and(query_param("id", oob_id))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "interactions": [
                {
                    "protocol": "dns",
                    "remote-address": "8.8.8.8",
                    "timestamp": "2026-05-25T12:00:00Z",
                    "raw-request": "A query"
                }
            ]
        })))
        .mount(&server)
        .await;

    let pm = Arc::new(ProxyManager::new(Vec::new(), false, ProxyMode::None, 1));
    let manager = OobInteractionManager::with_server_url(pm, server.uri());

    let hits = manager.poll_hits(oob_id).await.expect("poll should succeed");
    assert_eq!(hits.len(), 1, "Expected 1 hit, got {}. Server received {} requests", hits.len(), server.received_requests().await.unwrap().len());
    assert_eq!(hits[0].protocol, "dns");
    assert_eq!(hits[0].remote_address, "8.8.8.8");
}

/// E2E: Deterministic queue ID generation.
#[tokio::test]
async fn test_generate_id_for_queue_is_deterministic() {
    let id1 = OobInteractionManager::generate_id_for_queue(42);
    let id2 = OobInteractionManager::generate_id_for_queue(42);
    let id3 = OobInteractionManager::generate_id_for_queue(99);

    assert_eq!(id1, id2, "Same queue_id must produce same OOB ID");
    assert_eq!(id1.len(), 16, "OOB ID must be 16 hex chars");
    assert_ne!(id1, id3, "Different queue_id must produce different OOB ID");
}

/// E2E: wait_for_interaction returns None on timeout against empty mock.
#[tokio::test]
async fn test_oob_wait_timeout_no_hits() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/poll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "interactions": []
        })))
        .mount(&server)
        .await;

    let pm = Arc::new(ProxyManager::new(Vec::new(), false, ProxyMode::None, 1));
    let manager = OobInteractionManager::with_server_url(pm, server.uri());

    let result = manager.wait_for_interaction("any_id", 1).await.expect("wait should not error");
    assert!(result.is_none(), "No hits within timeout should return None");
}
