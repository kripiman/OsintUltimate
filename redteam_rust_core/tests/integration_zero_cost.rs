use redteam_rust_core::models::{Category, Finding, Severity, TargetHost};
use redteam_rust_core::plugins::intelligence::credential_leak::CredentialLeakScanner;
use redteam_rust_core::plugins::ScannerPlugin;
use std::sync::Arc;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

/// Zero-Cost Default Path E2E Audit.
///
/// Validates that with zero paid API keys and no optional binaries installed,
/// the engine emits at least one actionable CredentialLeak finding via the
/// always-free HIBP Pwned Passwords k-anonymity path.
#[tokio::test]
async fn test_zero_cost_path_emits_credential_leak_finding() {
    // Defense-in-depth: remove all paid env vars explicitly.
    // Constructor injection (with_params) below already bypasses env reads,
    // but remove_var ensures no downstream code path reads env directly.
    let paid_vars = [
        "HIBP_API_KEY",
        "SHODAN_API_KEY",
        "SHODAN_STUDENT_API_KEY",
        "FOFA_EMAIL",
        "FOFA_KEY",
        "ALIENVAULT_OTX_API_KEY",
        "ABUSEIPDB_API_KEY",
        "GREYNOISE_API_KEY",
        "LEAKIX_API_KEY",
        "GITHUB_TOKEN",
    ];
    for v in &paid_vars {
        std::env::remove_var(v);
    }

    // 1. Wiremock HIBP Pwned Passwords free endpoint (always-on, no key).
    let hibp_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/range/CBFDA"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "C6008F9CAB4083784CBD1874F76618D2A97:2254650\n"
        ))
        .mount(&hibp_server)
        .await;

    // 2. Synthetic target with a known pwned password in findings evidence.
    let target = TargetHost {
        host: "test.example.com".to_string(),
        findings: Arc::new(vec![
            Finding::new(
                "SYNTH-SECRET",
                Category::CredentialLeak,
                Severity::Medium,
                "Synthetic secret for zero-cost audit",
                serde_json::json!({"password": "password123"}),
            ),
        ]),
        ..Default::default()
    };

    // 3. Instantiate scanner with injected free-tier base URL.
    // HIBP_API_KEY is None → breached account path is gated off.
    let scanner = CredentialLeakScanner::with_params(
        reqwest::Client::new(),
        None, // HIBP_API_KEY absent
        10,
        50,
    ).with_base_urls(
        hibp_server.uri(), // pwned passwords base URL
        "https://haveibeenpwned.com".to_string(), // breached account (gated, won't call)
    );

    // 4. Run scan.
    let findings = scanner.scan(&target).await.unwrap();

    // 5. Assertions: zero-cost path must emit actionable findings.
    assert!(
        !findings.is_empty(),
        "Zero-cost path must emit at least 1 finding"
    );

    let cred_leak = findings
        .iter()
        .find(|f| f.core.category == Category::CredentialLeak)
        .expect("Must contain at least one CredentialLeak finding");

    let evidence = cred_leak
        .evidence
        .primary
        .as_ref()
        .expect("Finding must have evidence")
        .data
        .clone();

    assert_eq!(
        evidence["source"].as_str(),
        Some("hibp_pwned_passwords"),
        "Free path must use HIBP Pwned Passwords"
    );

    let pwned_count = evidence["password_pwned_count"].as_u64().unwrap_or(0);
    assert!(
        pwned_count > 0,
        "password_pwned_count must be > 0 (robust assertion; exact count varies if cached)"
    );
}
