/// Boot singleton initialization tests (Stage 8.D)
/// Verifies that ApiBudgetRegistry, ShodanKeyring, and ApiCache
/// can be initialized via the mem-only path without panicking.
#[cfg(test)]
mod tests {
    use redteam_rust_core::utils::api_budget::ApiBudgetRegistry;
    use redteam_rust_core::utils::api_cache::ApiCache;
    use redteam_rust_core::utils::shodan_keyring::ShodanKeyring;
    use redteam_rust_core::utils::config::Config;

    #[test]
    fn test_singletons_mem_only_no_panic() {
        let config = Config::from_env();
        // OnceLock::set returns Err if already set — safe to call multiple times
        ApiBudgetRegistry::init(&config, None);
        ShodanKeyring::init(&config);
        // get() must not panic after init
        let _ = ApiBudgetRegistry::get();
        let _ = ShodanKeyring::get();
        // ApiCache::global() returns None in mem-only path — expected behavior
        assert!(ApiCache::global().is_none());
    }
}
