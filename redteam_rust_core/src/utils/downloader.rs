use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::info;
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub async fn ensure_hysteria_binary() -> Result<PathBuf> {
    let bin_dir = dirs::home_dir()
        .context("Could not find home directory")?
        .join(".local/share/osintultimate/bin");
    
    if !bin_dir.exists() {
        fs::create_dir_all(&bin_dir).await?;
    }

    let bin_path = bin_dir.join("hysteria");
    if bin_path.exists() {
        return Ok(bin_path);
    }

    info!("🛡️ Hysteria binary not found locally. Starting auto-download...");
    
    // In a real scenario, we'd detect OS/arch. For this implementation, we assume Linux x86_64 as per user OS metadata.
    let url = "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64";
    
    let response = reqwest::get(url).await
        .context("Failed to download Hysteria binary")?;
    
    let content = response.bytes().await
        .context("Failed to read Hysteria binary content")?;
    
    let mut file = fs::File::create(&bin_path).await?;
    file.write_all(&content).await?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata().await?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&bin_path, perms).await?;
    }

    info!("🚀 Hysteria binary downloaded and verified at: {}", bin_path.display());
    Ok(bin_path)
}
