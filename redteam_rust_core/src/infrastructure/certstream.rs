use anyhow::Result;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tracing::{error, info, warn};

const CERTSTREAM_URL: &str = "wss://certstream.calidog.io";
const RECONNECT_BASE_SECS: u64 = 5;
const RECONNECT_MAX_SECS: u64 = 120;

pub struct CertStreamDaemon {
    keywords: Vec<String>,
    tx: mpsc::Sender<String>,
}

impl CertStreamDaemon {
    pub fn new(keywords: Vec<String>, tx: mpsc::Sender<String>) -> Self {
        Self { keywords, tx }
    }

    /// Spawn as background task. Returns immediately.
    pub fn spawn(keywords: Vec<String>) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(256);
        let daemon = Self::new(keywords, tx);
        tokio::spawn(async move {
            daemon.run().await;
        });
        rx
    }

    async fn run(self) {
        let mut backoff = RECONNECT_BASE_SECS;
        loop {
            info!("CertStreamDaemon: connecting to {}", CERTSTREAM_URL);
            match connect_async(CERTSTREAM_URL).await {
                Ok((ws, _)) => {
                    backoff = RECONNECT_BASE_SECS;
                    info!("CertStreamDaemon: connected");
                    if !self.process_stream(ws).await {
                        info!("CertStreamDaemon: stopping daemon as receiver is gone");
                        break;
                    }
                    warn!("CertStreamDaemon: stream ended, reconnecting in {}s", backoff);
                }
                Err(e) => {
                    error!("CertStreamDaemon: connect error: {}", e);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(RECONNECT_MAX_SECS);
        }
    }

    async fn process_stream<S>(&self, mut ws: S) -> bool
    where
        S: StreamExt<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        while let Some(msg_result) = ws.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    warn!("CertStreamDaemon: ws error: {}", e);
                    break;
                }
            };

            if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
                if let Some(domains) = self.extract_matching_domains(&text) {
                    for domain in domains {
                        // Exit if receiver is gone (main engine shutdown)
                        if self.tx.send(domain).await.is_err() {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    fn extract_matching_domains(&self, json_text: &str) -> Option<Vec<String>> {
        let v: serde_json::Value = serde_json::from_str(json_text).ok()?;

        if v.get("message_type")?.as_str()? != "certificate_update" {
            return None;
        }

        let all_domains = v
            .pointer("/data/leaf_cert/all_domains")?
            .as_array()?;

        let matches: Vec<String> = all_domains
            .iter()
            .filter_map(|d| d.as_str())
            .filter(|d| {
                let lower = d.to_lowercase();
                // Strip leading wildcard for matching
                let clean = lower.trim_start_matches("*.");
                self.keywords.iter().any(|kw| clean.contains(kw.as_str()))
            })
            .map(|d| d.trim_start_matches("*.").to_string())
            .collect();

        if matches.is_empty() { None } else { Some(matches) }
    }
}
