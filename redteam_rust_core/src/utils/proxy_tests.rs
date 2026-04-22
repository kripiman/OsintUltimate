use super::*;

#[tokio::test]
async fn test_proxy_manager_identity_bonding() {
    let p1 = "http://127.0.0.1:8080".to_string();
    let pm = ProxyManager::new(vec![p1.clone()], true, crate::utils::config::ProxyMode::Dante, 0);
    
    let host = "example.com";
    
    // First call should set the identity
    let (_, _client1) = pm.get_client(host).unwrap();
    
    // Second call to same host should have same identity (User-Agent)
    let (_, _client2) = pm.get_client(host).unwrap();
    
    // We can check if the identity_cache has the entry
    assert!(pm.identity_cache.contains_key(host));
    let ua1 = pm.identity_cache.get(host).unwrap().clone();
    
    let (_, _client3) = pm.get_client(host).unwrap();
    let ua2 = pm.identity_cache.get(host).unwrap().clone();
    
    assert_eq!(ua1, ua2, "User-Agent changed for the same host!");
    
    // Different host should (statistically) get a different UA, or at least a new entry
    let host2 = "other.com";
    let (_, _) = pm.get_client(host2).unwrap();
    assert!(pm.identity_cache.contains_key(host2));
}

#[tokio::test]
async fn test_proxy_manager_latency_prioritization() {
    let p1 = "http://127.0.0.1:8080".to_string();
    let p2 = "http://127.0.0.1:8081".to_string();
    let pm = ProxyManager::new(vec![p1.clone(), p2.clone()], true, crate::utils::config::ProxyMode::Dante, 0);

    // Report p1 as very fast, p2 as slow
    for _ in 0..5 {
        pm.report_latency(&p1, 50);
        pm.report_latency(&p2, 2000);
    }

    // Most calls should favor p1 (due to 10% random chance, we call it multiple times to be sure)
    let mut p1_hits = 0;
    for _ in 0..100 {
        if let Some((url, _)) = pm.get_client("test.com") {
            if url == p1 { p1_hits += 1; }
        }
    }
    
    assert!(p1_hits > 80, "Proxy manager did not favor low latency proxy. p1 hits: {}", p1_hits);
}

#[tokio::test]
async fn test_proxy_blacklist_recovery() {
    let proxies = vec!["http://127.0.0.1:8080".to_string()];
    let mut pm = ProxyManager::new(proxies, false, crate::utils::config::ProxyMode::Dante, 0);
    pm.blacklist_duration_sec = 1; // 1 second for test
    
    pm.blacklist_proxy("http://127.0.0.1:8080");
    assert!(pm.get_client("test.com").is_none());
    
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Should recover
    assert!(pm.get_client("test.com").is_some());
}

#[tokio::test]
async fn test_proxy_manager_concurrency() {
    let proxies = vec!["http://127.0.0.1:8080".to_string(), "http://127.0.0.1:8081".to_string()];
    let pm = Arc::new(ProxyManager::new(proxies, true, crate::utils::config::ProxyMode::Dante, 0));
    
    let mut handles = vec![];
    for i in 0..20 {
        let pm_clone = pm.clone();
        handles.push(tokio::spawn(async move {
            let host = format!("host{}.com", i % 3);
            let _ = pm_clone.get_client(&host);
        }));
    }
    
    for h in handles {
        let _ = h.await;
    }
}

#[tokio::test]
async fn test_proxy_manager_managed_exit_selection() {
    // No static proxies
    let pm = ProxyManager::new(vec![], true, crate::utils::config::ProxyMode::Dante, 0);
    assert!(pm.is_empty());
    assert!(pm.get_best_socks_url().is_none());

    // Add a managed exit
    let ip = "192.168.1.100".to_string();
    pm.add_managed_exit(ip.clone());

    assert!(!pm.is_empty());
    let socks_url = pm.get_best_socks_url().unwrap();
    assert_eq!(socks_url, "socks5h://192.168.1.100:1080");

    // Verify it gets picked by get_client
    let (_, _client) = pm.get_client("test.com").unwrap();
}
