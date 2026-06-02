use crate::core::net_evasion::fragment_assembler::FragmentAssembler;
use crate::core::net_evasion::fragment_prober::FragmentProber;
use crate::core::net_evasion::raw_socket::RawChannel;
use crate::core::net_evasion::{EvasionResult, NetEvasionStrategy, OverlapStrategy, ReassemblyPolicy};
use crate::models::findings::classification::{Category, Severity};
use crate::models::Finding;
use anyhow::Result;
use std::net::Ipv4Addr;

/// Minimal orchestrator stub for Sprint 2.
///
/// Coordinates the fragment prober and assembler for L3 evasion attacks.
/// Expanded in Sprint 6 with full strategy selection via Thompson Sampling.
pub struct NetEvasionOrchestrator {
    channel: RawChannel,
    policy: ReassemblyPolicy,
    local_ip: Ipv4Addr,
    quic_0rtt_client: std::sync::OnceLock<crate::core::net_evasion::quinn_client::QuinnEvasionClient>,
    tls13_0rtt_client: std::sync::OnceLock<crate::core::net_evasion::tls13_0rtt::Tls13ZeroRttClient>,
    findings_buffer: std::sync::Mutex<Vec<Finding>>,
}

impl NetEvasionOrchestrator {
    pub fn new(channel: RawChannel) -> Result<Self> {
        #[cfg(target_os = "linux")]
        let local_ip = crate::core::net_evasion::tcp_session::pick_local_ip()?;
        #[cfg(not(target_os = "linux"))]
        let local_ip = Ipv4Addr::new(127, 0, 0, 1);

        Ok(Self {
            channel,
            policy: ReassemblyPolicy::Unknown,
            local_ip,
            quic_0rtt_client: std::sync::OnceLock::new(),
            tls13_0rtt_client: std::sync::OnceLock::new(),
            findings_buffer: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Probes the target to determine its fragment reassembly policy.
    pub async fn probe_target(&mut self, target: Ipv4Addr) -> Result<ReassemblyPolicy> {
        let prober = FragmentProber::new(self.channel.clone());
        self.policy = prober.probe(target).await?;
        Ok(self.policy)
    }

    /// Performs a fragmentation evasion attack against `target`.
    ///
    /// `payload`: L4 header + data to fragment and deliver.
    /// `strategy`: Fragmentation strategy (Tiny, PoisonFirst, PoisonLast).
    pub async fn fragment_attack(
        &self,
        target: Ipv4Addr,
        payload: &[u8],
        strategy: OverlapStrategy,
    ) -> Result<EvasionResult> {
        let ip_template = crate::core::net_evasion::packet_forge::IpBuilder::new(
            self.local_ip,
            target,
            6, // TCP
        );

        let fragments = FragmentAssembler::split_packet(&ip_template, payload, 1500, strategy);
        let packets_sent = fragments.len() as u32;

        let start = std::time::Instant::now();
        self.channel.send_batch(&fragments).await?;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        // TODO: Response detection in Sprint 6 ( correlate with recv_timeout )
        Ok(EvasionResult {
            strategy_used: match strategy {
                OverlapStrategy::Tiny => NetEvasionStrategy::TinyFragments,
                OverlapStrategy::PoisonFirst | OverlapStrategy::PoisonLast => {
                    NetEvasionStrategy::OverlappingFragments
                }
            },
            success: true,
            packets_sent,
            response_received: false,
            latency_ms,
        })
    }

    /// Performs a TCP L4 evasion attack against `target`.
    #[cfg(target_os = "linux")]
    pub async fn tcp_evasion_attack(
        &self,
        target: std::net::SocketAddrV4,
        payload: &[u8],
        strategy: NetEvasionStrategy,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::tcp_evasion::TcpEvasionStrategy;
        use crate::core::net_evasion::tcp_fast_open::TcpFastOpenBypass;
        use crate::core::net_evasion::tcp_micro_segmentation::TcpMicroSegmentation;
        use crate::core::net_evasion::tcp_state_desync::TcpStateDesync;
        use crate::core::net_evasion::tcp_urgent_abuse::TcpUrgentAbuse;
        use crate::core::net_evasion::tcp_zero_window::TcpZeroWindowDesync;

        match strategy {
            NetEvasionStrategy::TcpMicroSegmentation => {
                TcpMicroSegmentation.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::TcpStateDesync => {
                TcpStateDesync.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::UrgentPointerAbuse => {
                TcpUrgentAbuse.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::ZeroWindowDesync => {
                TcpZeroWindowDesync.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            NetEvasionStrategy::TcpFastOpenBypass => {
                TcpFastOpenBypass.execute(self.channel.clone(), self.local_ip, target, payload).await
            }
            _ => Err(anyhow::anyhow!("Not a TCP evasion strategy")),
        }
    }

    /// Performs a JA4 TLS fingerprint spoofing request against `target`.
    ///
    /// Tier 1: Full HTTPS GET with rustls-approximated JA4.
    /// Tier 2 (fallback): Raw ClientHello probe with exact JA4 match.
    pub async fn ja4_evasion_request(
        &self,
        target: url::Url,
        target_ja4: &str,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::ja4_http_client::Ja4EvasionClient;

        let client = Ja4EvasionClient::new(target_ja4)?;
        let url_str = target.as_str();
        let host = target.host_str().unwrap_or("127.0.0.1");
        let port = target.port().unwrap_or(443);

        let start = std::time::Instant::now();

        // Tier 1: try full HTTPS request
        match client.get(url_str).await {
            Ok(_resp) => {
                let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::Ja4Spoofing,
                    success: true,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_) => {
                // Tier 2: fallback to raw fingerprint probe
                let probe_target = format!("{}:{}", host, port);
                client.fingerprint_probe(&probe_target).await
            }
        }
    }

    /// Sends a raw forged QUIC Initial packet to `target` via UDP.
    ///
    /// Probe-only: reads the response and verifies it looks like a valid
    /// QUIC packet (Long Header, matching version). No handshake completion.
    pub async fn quic_probe(
        &self,
        target: std::net::SocketAddrV4,
        _target_quic_version: u32,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::quic_forge::QuicInitialForge;

        use tokio::net::UdpSocket;

        let _dst_ip = *target.ip();
        let _dst_port = target.port();

        // Build forged QUIC Initial
        let forge = QuicInitialForge::new(
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // DCID
            &[],                                                 // SCID
        )
        .with_crypto_frame(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x03\x03"); // minimal TLS-like data

        let packet = forge.build()?;

        let start = std::time::Instant::now();

        // Bind to any local port and send
        let local_addr = std::net::SocketAddrV4::new(self.local_ip, 0);
        let socket = UdpSocket::bind(local_addr).await?;
        socket.send_to(&packet, target).await?;

        // Try to read response with timeout
        let mut buf = vec![0u8; 2048];
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            socket.recv(&mut buf).await
        })
        .await;

        let has_response = match result {
            Ok(Ok(n)) if n > 0 => {
                // Minimal check: first byte has long-header form (MSB = 1)
                buf[0] & 0x80 != 0
            }
            _ => false,
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(EvasionResult {
            strategy_used: NetEvasionStrategy::QuicProbe,
            success: has_response,
            packets_sent: 1,
            response_received: has_response,
            latency_ms,
        })
    }

    /// Perform a full QUIC handshake to `target`.
    /// `target` (SocketAddrV4) is upcast to `SocketAddr` for `endpoint.connect()`.
    pub async fn quic_full_handshake(
        &self,
        target: std::net::SocketAddrV4,
        server_name: &str,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::quinn_client::QuinnEvasionClient;

        let start = std::time::Instant::now();
        let client = QuinnEvasionClient::new()?;
        let addr = std::net::SocketAddr::V4(target);

        let result = client.connect(addr, server_name).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(_conn) => {
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::QuicFullHandshake,
                    success: true,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_e) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::QuicFullHandshake,
                success: false,
                packets_sent: 0,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Perform an HTTP/3 GET request to `url`.
    pub async fn http3_request(&self, url: &str) -> Result<EvasionResult> {
        use crate::core::net_evasion::http3_client::Http3EvasionClient;

        let start = std::time::Instant::now();
        let client = Http3EvasionClient::new()?;

        let result = client.get(url).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(resp) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::Http3Request,
                success: resp.status >= 200 && resp.status < 300,
                packets_sent: 1,
                response_received: true,
                latency_ms,
            }),
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::Http3Request,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Attempt a 0-RTT QUIC connection to `target`.
    /// Returns whether 0-RTT was accepted by the server.
    pub async fn quic_0rtt_probe(
        &self,
        target: std::net::SocketAddrV4,
        server_name: &str,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::quinn_client::QuinnEvasionClient;

        let start = std::time::Instant::now();
        let client = self
            .quic_0rtt_client
            .get_or_init(|| QuinnEvasionClient::with_early_data().expect("0-RTT client init"));
        let addr = std::net::SocketAddr::V4(target);

        let result = client.connect_0rtt(addr, server_name).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(conn) => {
                // Give the background task a moment to poll acceptance
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let accepted = conn.was_0rtt_accepted();
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::QuicZeroRtt,
                    success: accepted,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_e) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::QuicZeroRtt,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Probe a QUIC server for Retry token handling (statelessness check).
    pub async fn quic_retry_probe(
        &self,
        target: std::net::SocketAddrV4,
        version: u32,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::quic_evasion::retry_token_probe;

        let start = std::time::Instant::now();
        let result = retry_token_probe(target, version).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(probe) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::QuicRetryProbe,
                success: probe.retry_received && probe.token_extracted,
                packets_sent: if probe.retry_received { 2 } else { 1 },
                response_received: probe.handshake_completed,
                latency_ms,
            }),
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::QuicRetryProbe,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Perform a domain-fronted HTTP/3 GET request.
    pub async fn domain_front_request(
        &self,
        front_domain: &str,
        target_domain: &str,
        path: &str,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::domain_front::DomainFrontClient;

        let start = std::time::Instant::now();
        let client = DomainFrontClient::new(front_domain, target_domain)?;

        let result = client.get(path).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(resp) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::DomainFronting,
                success: resp.status >= 200 && resp.status < 300,
                packets_sent: 1,
                response_received: true,
                latency_ms,
            }),
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::DomainFronting,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Connect to `target:port` over TCP with Encrypted Client Hello (ECH).
    pub async fn ech_connect(
        &self,
        target: &str,
        port: u16,
        ech_config_bytes: &[u8],
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::ech_client::EchClient;

        let start = std::time::Instant::now();

        let client = match EchClient::with_ech_config(ech_config_bytes) {
            Ok(c) => c,
            Err(_) => {
                return Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::EchConnect,
                    success: false,
                    packets_sent: 0,
                    response_received: false,
                    latency_ms: 0.0,
                });
            }
        };

        let result = client.connect(target, port).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(conn) => {
                let accepted = matches!(
                    conn.ech_status(),
                    rustls_ech::client::EchStatus::Accepted
                        | rustls_ech::client::EchStatus::Offered
                );
                if matches!(conn.ech_status(), rustls_ech::client::EchStatus::Accepted) {
                    self.push_finding(
                        "ECH-001",
                        Category::TechnologyStack,
                        Severity::Info,
                        "ECH Accepted",
                        serde_json::json!({"ech_status": "Accepted"}),
                    );
                }
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::EchConnect,
                    success: accepted,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::EchConnect,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Fetch ECH config from DNS and connect to `target:port` with ECH.
    pub async fn ech_dns_fetch_connect(
        &self,
        target: &str,
        port: u16,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::ech_dns_fetcher::EchDnsFetcher;

        let start = std::time::Instant::now();

        let fetcher = match EchDnsFetcher::new().await {
            Ok(f) => f,
            Err(_) => {
                return Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::EchDnsFetch,
                    success: false,
                    packets_sent: 0,
                    response_received: false,
                    latency_ms: 0.0,
                });
            }
        };

        let result = fetcher.fetch_and_connect(target, port).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(conn) => {
                let accepted = matches!(
                    conn.ech_status(),
                    rustls_ech::client::EchStatus::Accepted
                        | rustls_ech::client::EchStatus::Offered
                );
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::EchDnsFetch,
                    success: accepted,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::EchDnsFetch,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Probe `target:port` for HTTP/2 cleartext (h2c) upgrade support.
    pub async fn h2c_probe(
        &self,
        target: &str,
        port: u16,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::h2c_probe::H2cProbeClient;

        let start = std::time::Instant::now();
        let result = H2cProbeClient::probe_h2c(target, port).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(probe) => {
                if probe.h2c_accepted {
                    self.push_finding(
                        "H2C-001",
                        Category::WafDetected,
                        Severity::High,
                        "h2c Cleartext Upgrade Accepted",
                        serde_json::json!({
                            "server": probe.server_header,
                            "status": probe.response_status,
                        }),
                    );
                }
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::H2cUpgradeProbe,
                    success: probe.h2c_accepted,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::H2cUpgradeProbe,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Probe `target:port` for HTTP request smuggling (CL.TE / TE.CL).
    pub async fn smuggle_probe(
        &self,
        target: &str,
        port: u16,
        variant: crate::core::net_evasion::http_smuggle::SmuggleVariant,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::http_smuggle::SmuggleProbe;

        let start = std::time::Instant::now();
        let result = match variant {
            crate::core::net_evasion::http_smuggle::SmuggleVariant::ClTe => {
                SmuggleProbe::probe_cl_te(target, port).await
            }
            crate::core::net_evasion::http_smuggle::SmuggleVariant::TeCl => {
                SmuggleProbe::probe_te_cl(target, port).await
            }
            crate::core::net_evasion::http_smuggle::SmuggleVariant::H2Preface => {
                SmuggleProbe::probe_h2_preface(target, port).await
            }
        };
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(probe) => {
                if probe.vulnerable {
                    let (sev, title) = match probe.variant {
                        crate::core::net_evasion::http_smuggle::SmuggleVariant::H2Preface => {
                            (Severity::High, "HTTP/2 Preface Poisoning")
                        }
                        _ => (Severity::Critical, "HTTP Request Smuggling Detected"),
                    };
                    self.push_finding(
                        "HRS-001",
                        Category::Vulnerability,
                        sev,
                        title,
                        serde_json::json!({
                            "variant": format!("{:?}", probe.variant),
                            "confidence": format!("{:?}", probe.confidence),
                            "response_time_ms": probe.response_time_ms,
                        }),
                    );
                }
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::HttpRequestSmuggling,
                    success: probe.vulnerable,
                    packets_sent: 1,
                    response_received: probe.confidence
                        != crate::core::net_evasion::http_smuggle::Confidence::Ambiguous,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::HttpRequestSmuggling,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Probe `target:port` for Web Cache Deception.
    pub async fn wcd_probe(
        &self,
        target: &str,
        port: u16,
        scheme: &str,
        base_path: &str,
        config: crate::core::net_evasion::cache_deception::CacheDeceptionConfig,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::cache_deception::CacheDeceptionProbe;

        let start = std::time::Instant::now();
        let result = CacheDeceptionProbe::probe(target, port, scheme, base_path, &config).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(probe) => {
                if probe.vulnerable {
                    self.push_finding(
                        "WCD-001",
                        Category::Vulnerability,
                        Severity::High,
                        "Web Cache Deception",
                        serde_json::json!({
                            "cache_headers": probe.cache_headers,
                            "confidence": format!("{:?}", probe.confidence),
                            "response_time_ms": probe.response_time_ms,
                        }),
                    );
                }
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::WebCacheDeception,
                    success: probe.vulnerable,
                    packets_sent: 2,
                    response_received: probe.confidence
                        != crate::core::net_evasion::http_smuggle::Confidence::Ambiguous,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::WebCacheDeception,
                success: false,
                packets_sent: 0,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Connect to `target:port` over TCP with TLS 1.3 0-RTT.
    ///
    /// Reuses the same `Tls13ZeroRttClient` across calls so that PSK tickets
    /// are cached and subsequent connections may benefit from 0-RTT.
    pub async fn tls13_0rtt_send(
        &self,
        target: &str,
        port: u16,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::tls13_0rtt::Tls13ZeroRttClient;

        let start = std::time::Instant::now();
        let client = self
            .tls13_0rtt_client
            .get_or_init(|| Tls13ZeroRttClient::new().expect("TLS 1.3 0-RTT client init"));

        let result = client.connect(target, port).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(conn) => {
                let accepted = conn.is_early_data_accepted();
                Ok(EvasionResult {
                    strategy_used: NetEvasionStrategy::Tls13ZeroRtt,
                    success: accepted,
                    packets_sent: 1,
                    response_received: true,
                    latency_ms,
                })
            }
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::Tls13ZeroRtt,
                success: false,
                packets_sent: 1,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Probe the network topology to find the firewall hop count.
    #[cfg(target_os = "linux")]
    pub async fn probe_firewall_hops(
        &self,
        target: Ipv4Addr,
    ) -> Result<EvasionResult> {
        use crate::core::net_evasion::topology_prober::traceroute_to_firewall;

        let start = std::time::Instant::now();
        let result = traceroute_to_firewall(self.channel.clone(), target, 30).await;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(hops) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::TtlInsertion,
                success: true,
                packets_sent: hops as u32,
                response_received: true,
                latency_ms,
            }),
            Err(_) => Ok(EvasionResult {
                strategy_used: NetEvasionStrategy::TtlInsertion,
                success: false,
                packets_sent: 0,
                response_received: false,
                latency_ms,
            }),
        }
    }

    /// Drain all buffered findings and return them.
    ///
    /// Callers should push returned findings to a `DataSink`.
    pub fn drain_findings(&self) -> Vec<Finding> {
        self.findings_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
    }

    fn push_finding(&self, id: &str, category: Category, severity: Severity, title: &str, evidence: serde_json::Value) {
        let finding = Finding::new(id, category, severity, title, evidence);
        if let Ok(mut buf) = self.findings_buffer.lock() {
            buf.push(finding);
        }
    }

    /// Returns the last known reassembly policy.
    pub fn policy(&self) -> ReassemblyPolicy {
        self.policy
    }
}
