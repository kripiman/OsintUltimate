use super::*;
use crate::plugins::GlobalConfig;
use crate::utils::executor::GhostMode;
use tempfile::tempdir;

#[tokio::test]
async fn test_mcp_two_level_cache() -> anyhow::Result<()> {
    let config = GlobalConfig::<GhostMode>::new();
    let mut server = McpServer::new(config);
    
    // Setup SQLite cache
    let tmp_dir = tempdir()?;
    let db_path = tmp_dir.path().join("mcp_test.db");
    server = server.with_postgres(db_path.clone()).await;
    
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
