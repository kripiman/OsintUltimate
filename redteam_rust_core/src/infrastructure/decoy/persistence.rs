use anyhow::{Result, Context};
use tokio::sync::mpsc;
use tracing::{info, error};
use super::models::TripwireEvent;

/// Spawns a background task that drains TripwireEvents from the channel
/// and persists them into SQLite (WAL mode). This decouples the listener
/// from database I/O for backpressure.
pub async fn spawn_tripwire_persister(
    mut rx: mpsc::Receiver<TripwireEvent>,
    db_url: &str,
) -> Result<tokio::task::JoinHandle<()>> {
    let pool = sqlx::PgPool::connect(db_url).await
        .context("Failed to connect to tripwire SQLite database")?;

    // Ensure WAL mode + create table
    
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tripwire_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fqdn TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            user_agent TEXT,
            headers_json TEXT,
            ja3_hash TEXT,
            triggered_at TEXT NOT NULL
        )"
    ).execute(&pool).await?;

    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Err(e) = sqlx::query(
                "INSERT INTO tripwire_events (fqdn, source_ip, method, path, user_agent, headers_json, ja3_hash, triggered_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
                .bind(&event.fqdn)
                .bind(&event.source_ip)
                .bind(&event.method)
                .bind(&event.path)
                .bind(&event.user_agent)
                .bind(&event.headers_json)
                .bind(&event.ja3_hash)
                .bind(event.triggered_at.to_rfc3339())
                .execute(&pool)
                .await
            {
                error!("🚨 TRIPWIRE: Failed to persist event: {}", e);
            }
        }
        info!("🍯 DECOY: Tripwire persister shutting down.");
    });

    Ok(handle)
}
