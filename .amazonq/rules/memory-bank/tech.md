# OsintUltimate — Technology Stack

## Language & Runtime
- **Rust** (stable, edition 2021)
- **Tokio** async runtime (`features = ["full"]`) — multi-threaded worker pool
- **io-uring** (`io-uring = "0.7"`) — kernel-bypass I/O for native scanner

## Build & Run
```bash
# Build release binary
cd redteam_rust_core
cargo build --release

# Run with target
./target/release/redteam_rust_core example.com

# Docker (Alpine, statically linked musl)
docker compose --profile base run osintultimate example.com
docker compose --profile privileged run osintultimate-priv example.com --vuln-scan
docker compose --profile full up -d  # includes Ollama + Jaeger

# Check compilation errors
cargo check 2> check_errors.txt
```

## Key Dependencies (Cargo.toml)
| Crate | Version | Purpose |
|---|---|---|
| `tokio` | 1.28 | Async runtime |
| `reqwest` | 0.11 | HTTP client (rustls-tls, socks, gzip) |
| `axum` | 0.7 | Web dashboard + MCP server |
| `sqlx` | 0.7 | SQLite WAL persistence |
| `dashmap` | 5.5 | Lock-free concurrent HashMap |
| `crossbeam` | 0.8 | Lock-free queues (`SegQueue`, `ArrayQueue`) |
| `moka` | 0.10 | Async TTL cache (AI analysis, tool schemas) |
| `ed25519-dalek` | 2.1 | Plugin signature verification, dashboard JWT |
| `hickory-resolver` | 0.24 | Async DNS with DoH support |
| `bloomfilter` | 1.0 | Subdomain deduplication |
| `io-uring` | 0.7 | Native SYN scanner |
| `smoltcp` | 0.11 | Raw socket/TCP stack |
| `aya` | 0.13 | eBPF integration |
| `libloading` | 0.9 | Dynamic plugin `.so` loading |
| `handlebars` | 4.3 | HTML report templating |
| `clap` | 4.3 | CLI argument parsing (derive) |
| `inquire` | 0.6 | Interactive TUI menu |
| `tracing` + `tracing-subscriber` | 0.1/0.3 | Structured logging + OTLP export |
| `opentelemetry-otlp` | 0.14 | Jaeger/OTLP telemetry |
| `serde` + `serde_json` | 1.0 | Serialization |
| `regex` | 1.9 | Pattern matching (secret scrubbing, arg validation) |
| `rand` + `rand_distr` | 0.8/0.4 | Jitter, random ports, LogNormal delays |
| `sha2` | 0.10 | Plugin integrity, CVE cache |
| `flate2` | 1.0 | Gzip compression for webhook sink |
| `siphasher` | 0.3 | HashDoS-resistant cache keys |
| `once_cell` | 1.21 | Static lazy initialization |
| `uuid` | 1.4 | Finding/session IDs |
| `chrono` | 0.4 | Timestamps |
| `anyhow` + `thiserror` | 1.0 | Error handling |
| `async-trait` | 0.1 | Async trait methods |

## Build Profiles
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true  # Strips symbols for smaller binary
```

## Docker Architecture
- **Builder stage**: `rust:1-alpine` with musl target (`x86_64-unknown-linux-musl`)
- **Runner stage**: `alpine:latest` with nmap, nuclei, httpx, subfinder, naabu, ffuf, sqlmap
- Static binary via `RUSTFLAGS="-C target-feature=+crt-static"`
- Non-root user `redteam` (UID 1000)

## Environment Variables
```bash
# AI Providers
GEMINI_API_KEYS=key1,key2,...
AZURE_OPENAI_ENDPOINT=https://...
AZURE_OPENAI_KEY=...
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
OLLAMA_URL=http://localhost:11434

# Infrastructure
DIGITALOCEAN_TOKEN=...
GLOBAL_SCAN_PROXY=socks5h://127.0.0.1:9050
PROXY_MODE=dante|shadowsocks|hysteria
PROXY_POOL_SIZE=3

# OSINT APIs
SHODAN_API_KEY=...
NETLAS_API_KEY=...
CHAOS_API_KEY=...
SECURITYTRAILS_API_KEY=...
GITHUB_TOKEN=...

# Limits
SOFT_MEMORY_LIMIT=600   # MB
HARD_MEMORY_LIMIT=900   # MB
MAX_TOKENS=4096

# Security
OSINT_PLUGIN_PUBKEY=<hex ed25519 pubkey>  # Required for dynamic plugins
MCP_TOKEN=...
```

## CI/CD
- GitHub Actions: `.github/workflows/ci.yml`, `release.yml`
- Azure Pipelines: `azure-pipelines.yml`

## Telemetry
- OpenTelemetry OTLP → Jaeger (`OTEL_ENDPOINT` env var)
- Sensitive data masked in logs via `MaskingWriter` regex filter
- JSON structured logs via `--json-logs` flag
