use super::*;
use crate::plugins::GlobalConfig;
use crate::utils::executor::GhostMode;

#[tokio::test]
async fn test_mcp_two_level_cache() -> anyhow::Result<()> {
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;
    use tempfile::tempdir;

    let db_url = match std::env::var("REDTEAM_TEST_DB_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("⊘ SKIP test_mcp_two_level_cache: REDTEAM_TEST_DB_URL not set");
            return Ok(());
        }
    };
    let _pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("⊘ SKIP test_mcp_two_level_cache: connect failed: {e}");
            return Ok(());
        }
    };

    // Temporarily set DATABASE_URL to REDTEAM_TEST_DB_URL so PostgresSink::new uses it
    let old_db_url = std::env::var("DATABASE_URL").ok();
    std::env::set_var("DATABASE_URL", &db_url);

    // Dynamic temp path isolation with standard/sovereign subdirs
    let tmp = tempdir()?;
    let sovereign_dir = tmp.path().join("sovereign");
    let standard_dir = tmp.path().join("standard");
    std::fs::create_dir_all(&sovereign_dir)?;
    std::fs::create_dir_all(&standard_dir)?;

    let db_path = standard_dir.join("mcp_test.db");

    let config = GlobalConfig::<GhostMode>::new();
    let mut server = McpServer::new(config);
    
    let server_res = server.with_postgres(db_path).await;

    if let Some(ref val) = old_db_url {
        std::env::set_var("DATABASE_URL", val);
    } else {
        std::env::remove_var("DATABASE_URL");
    }

    server = server_res;

    // Check if server database was initialized
    if server.db.is_none() {
        eprintln!("⊘ SKIP test_mcp_two_level_cache: database connection not established");
        return Ok(());
    }

    let cache_key = "TestPlugin:test.com";
    let test_output = "Compressed Result v14.1";

    // 1. Initial State: Cache is empty
    assert!(server.plugin_cache.get(cache_key).is_none());
    if let Some(ref db) = server.db {
        assert!(db.load_plugin_cache(cache_key).await?.is_none());
    }

    // 2. Save to cache (Simulating plugin execution)
    server.plugin_cache.insert(cache_key.to_string(), test_output.to_string()).await;
    if let Some(ref db) = server.db {
        db.save_plugin_cache(cache_key, test_output).await?;
    }

    // 3. Level 1 Hit (RAM)
    assert_eq!(server.plugin_cache.get(cache_key), Some(test_output.to_string()));

    // 4. Level 2 Hit (Disk) - Clear RAM first
    server.plugin_cache.invalidate(cache_key).await;
    assert!(server.plugin_cache.get(cache_key).is_none());
    
    if let Some(ref db) = server.db {
        let disk_hit = db.load_plugin_cache(cache_key).await?;
        assert_eq!(disk_hit, Some(test_output.to_string()));
        
        // Repopulate RAM
        server.plugin_cache.insert(cache_key.to_string(), disk_hit.unwrap()).await;
    }
    
    assert_eq!(server.plugin_cache.get(cache_key), Some(test_output.to_string()));

    Ok(())
}
