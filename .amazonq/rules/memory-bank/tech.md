# Technology Stack

## Programming Languages
- **Rust 2021 Edition**: Core engine implementation
- **Python 3.x**: Embedded tools (graphw00f)
- **JavaScript/Node.js**: Supply chain analysis (retire.js)

## Core Dependencies

### Async Runtime & Concurrency
- **tokio 1.28** (full features): Async runtime foundation
- **futures 0.3**: Future combinators and utilities
- **async-trait 0.1**: Async trait support
- **crossbeam 0.8**: Lock-free concurrent data structures
- **async-stream 0.3.6**: Async stream macros

### Networking & HTTP
- **reqwest 0.11**: HTTP client with rustls-tls, gzip, socks, multipart
- **axum 0.7**: Web framework for API and UI
- **tower-http 0.5**: HTTP middleware (CORS, tracing, file serving)
- **tower_governor 0.8.0**: Rate limiting
- **tokio-tungstenite 0.21**: WebSocket client (CertStream)
- **tokio-socks 0.5.2**: SOCKS proxy support
- **hickory-resolver 0.24**: DNS resolution with DoH support

### Data Structures & Caching
- **dashmap 5.5**: Concurrent HashMap
- **moka 0.10**: High-performance caching with TTL
- **bloomfilter 1.0**: Probabilistic deduplication
- **siphasher 0.3**: Fast hashing

### Serialization & Data Formats
- **serde 1.0**: Serialization framework
- **serde_json 1.0**: JSON support
- **quick-xml 0.31**: XML parsing with serialization
- **toml 1.1.2**: TOML configuration parsing

### Database & Persistence
- **sqlx 0.7**: Async PostgreSQL driver with compile-time query checking
  - Features: runtime-tokio-rustls, postgres, chrono, macros, json
- **migrations/**: SQL schema migrations for PostgreSQL

### CLI & User Interface
- **clap 4.3**: Command-line argument parsing with derive macros
- **indicatif 0.17**: Progress bars and spinners
- **inquire 0.6**: Interactive prompts

### Logging & Observability
- **tracing 0.1**: Structured logging framework
- **tracing-subscriber 0.3**: Log formatting with env-filter and json
- **tracing-opentelemetry 0.22**: OpenTelemetry integration
- **opentelemetry 0.21**: Distributed tracing
- **opentelemetry-otlp 0.14**: OTLP exporter

### Error Handling
- **anyhow 1.0**: Flexible error handling
- **thiserror 1.0**: Custom error types with derive macros

### Cryptography & Security
- **ed25519-dalek 2.1**: EdDSA signatures
- **sha2 0.10**: SHA-2 hashing
- **base64 0.21**: Base64 encoding/decoding
- **hex 0.4**: Hex encoding/decoding

### File System & Templating
- **tempfile 3.8**: Temporary file management
- **walkdir 2.3**: Recursive directory traversal
- **handlebars 4.3**: Template engine for reports
- **rust-embed 8.4**: Embed static assets in binary
- **mime_guess 2.0**: MIME type detection

### Utilities
- **chrono 0.4**: Date and time handling
- **uuid 1.4**: UUID generation (v4)
- **url 2.4**: URL parsing and manipulation
- **regex 1.9**: Regular expressions
- **rand 0.8**: Random number generation
- **rand_distr 0.4**: Random distributions
- **which 4.4**: Executable path resolution
- **dirs 5.0.1**: Standard directory paths
- **addr 0.15**: IP address utilities
- **html-escape 0.2**: HTML escaping
- **urlencoding 2.1**: URL encoding

### Advanced Networking
- **io-uring 0.7**: Linux io_uring support for high-performance I/O
- **smoltcp 0.11**: TCP/IP stack implementation
- **socket2 0.5**: Low-level socket operations
- **aya 0.13**: eBPF support

### Compression & Archives
- **flate2 1.0.28**: Gzip compression
- **zip 8.5.1**: ZIP archive handling

### Security Analysis
- **cvss 2.2.0**: CVSS score calculation

### System Integration
- **once_cell 1.21.3**: Lazy static initialization
- **rustix 1.1.3**: Safe system calls (process features)
- **libc 0.2.182**: C library bindings
- **dotenv 0.15.0**: Environment variable loading
- **libloading 0.9.0**: Dynamic library loading
- **sysinfo 0.30.5**: System information gathering

### Stream Processing
- **tokio-util 0.7.18**: Tokio utilities (io, io-util)
- **tokio-stream 0.1**: Stream utilities

### gRPC & RPC
- **tonic 0.9**: gRPC framework
- **tower 0.4**: Service abstraction layer

## Build Configuration

### Cargo Features
- **default**: ["bug-bounty"]
- **bug-bounty**: Base feature set
- **ai-redteam**: AI-powered red teaming (includes bug-bounty)
- **mobile**: Mobile security testing (includes bug-bounty)
- **sovereign**: Full feature set (bug-bounty + mobile + ai-redteam)

### Release Profile
```toml
[profile.release]
opt-level = 3              # Maximum optimization
lto = true                 # Link-time optimization
codegen-units = 1          # Single codegen unit for better optimization
strip = true               # Strip symbols for smaller binary
```

## External Tools & Binaries

### Reconnaissance
- subfinder, amass, dnsx, httpx, nmap, masscan

### Web Security
- nuclei, sqlmap, xsstrike, nikto, wappalyzer, graphw00f, crackql, schemathesis

### Cloud Security
- scoutsuite, prowler, cloudmapper

### Container Security
- grype, syft, cosign

### Mobile Security
- apktool, jadx, mobsf

### Exploitation
- metasploit, ligolo

### Supply Chain
- retire.js (Node.js dependency)

## Infrastructure Requirements

### Runtime Dependencies
- **Docker**: Container isolation for security tools
- **PostgreSQL**: Data persistence and distributed queue
- **OpenSSL/libssl-dev**: TLS support

### Cloud Services
- **DigitalOcean API**: VPS rotation for stealth operations
- **AI Backends**: Ollama (local), Claude CLI, OpenAI API, Kimi API

### OSINT APIs
- Chaos, Netlas, Shodan, SecurityTrails, VirusTotal

## Development Commands

```bash
# Build release binary
cargo build --release

# Run with full features
cargo run --release --features sovereign -- --target example.com

# Run tests
cargo test

# Check without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy

# Build Docker image
docker build -t osintultimate:latest .

# Run with Docker Compose
docker-compose up -d
```

## Environment Configuration
Configuration via `.env.oracle` file:
- DIGITALOCEAN_TOKEN: VPS provisioning
- OLLAMA_API_URL: Local AI inference
- OPENAI_API_KEY: GPT-4 access
- CLAUDE_API_KEY: Claude access
- KIMI_API_KEY: Kimi K2.6 access
- DATABASE_URL: PostgreSQL connection string
- Various OSINT API keys
