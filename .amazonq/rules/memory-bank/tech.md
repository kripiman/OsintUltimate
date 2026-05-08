# OsintUltimate - Technology Stack

## Core Technologies

### Programming Languages
- **Primary**: Rust (2021 edition)
- **Build System**: Cargo
- **Version**: Stable Rust toolchain

### Runtime & Async
- **Async Runtime**: Tokio 1.28 (full features)
- **Futures**: futures 0.3
- **Async Traits**: async-trait 0.1

### Serialization & Data Handling
- **JSON**: serde_json 1.0
- **Serialization**: serde 1.0 with derive features
- **Dates**: chrono 0.4 with serde support
- **UUID**: uuid 1.4 (v4, serde)
- **URL Parsing**: url 2.4
- **Regex**: regex 1.9
- **Random**: rand 0.8, rand_distr 0.4
- **XML**: quick-xml 0.31 with serialize
- **Caching**: moka 0.10 with future support
- **Concurrent Maps**: dashmap 5.5
- **Atomic Reference**: arc-swap 1.7
- **Concurrency**: crossbeam 0.8
- **Bloom Filters**: bloomfilter 1.0

### Networking & HTTP
- **HTTP Client**: reqwest 0.11 (json, rustls-tls, gzip, stream, socks, multipart)
- **DNS Resolution**: hickory-resolver 0.24 (tokio-rustls, system-config, dns-over-https-rustls)
- **WebSocket**: tokio-tungstenite 0.21 with rustls-tls-webpki-roots
- **High-Perf Networking**: io-uring 0.7, smoltcp 0.11
- **Sockets**: socket2 0.5, tokio-socks 0.5.2
- **NATS**: async-nats 0.35

### CLI & User Interface
- **CLI Framework**: clap 4.3 with derive
- **Progress Bars**: indicatif 0.17
- **Interactive Prompts**: inquire 0.6

### Logging & Observability
- **Structured Logging**: tracing 0.1, tracing-subscriber 0.3
- **OpenTelemetry**: tracing-opentelemetry 0.22, opentelemetry 0.21
- **OTLP Export**: opentelemetry-otlp 0.14
- **gRPC**: tonic 0.9
- **Middleware**: tower 0.4

### Error Handling
- **Any Error**: anyhow 1.0
- **Custom Errors**: thiserror 1.0

### Cryptography & Security
- **Digital Signatures**: ed25519-dalek 2.1 with rand_core
- **Encoding**: hex 0.4, base64 0.21
- **Hashing**: sha2 0.10
- **CVSS Scoring**: cvss 2.2.0

### File System & Templating
- **Temporary Files**: tempfile 3.8
- **Directory Walking**: walkdir 2.3
- **Templating**: handlebars 4.3
- **IO Utilities**: tokio-util 0.7.18
- **Path Resolution**: which 4.4
- **System Info**: sysinfo 0.30.5
- **Compression**: flate2 1.0.28, zip 8.5.1

### Web Framework
- **Web Server**: axum 0.7 (macros, multipart)
- **HTTP Middleware**: tower-http 0.5 (fs, cors, trace)
- **Rate Limiting**: tower_governor 0.8.0 with axum
- **Static Files**: rust-embed 8.4
- **MIME Types**: mime_guess 2.0

### Database
- **PostgreSQL**: sqlx 0.7 (runtime-tokio-rustls, postgres, chrono, macros, json)
- **Migrations**: SQL files in migrations/ directory

### System Integration
- **Environment Variables**: dotenv 0.15.0
- **Dynamic Loading**: libloading 0.9.0
- **System Calls**: rustix 1.1.3 with process feature
- **Libc Bindings**: libc 0.2.182

### Text Processing
- **HTML Escaping**: html-escape 0.2
- **URL Encoding**: urlencoding 2.1
- **TOML Parsing**: toml 1.1.2

## Build Configuration

### Cargo.toml Features
```toml
[features]
default = ["bug-bounty"]
bug-bounty = []                    # Normal operations
ai-redteam = ["bug-bounty"]        # AI-powered red team
mobile = ["bug-bounty"]            # Mobile security testing
sovereign = ["bug-bounty", "mobile", "ai-redteam"]  # Full APT mode
```

### Release Profile
```toml
[profile.release]
opt-level = 3      # Maximum optimization
lto = true         # Link-time optimization
codegen-units = 1  # Single codegen unit
strip = true       # Strip symbols for smaller binary
```

## System Dependencies

### Required System Packages
- **Rust**: Stable toolchain
- **Docker**: Container runtime for tool isolation
- **PostgreSQL**: Database server (v12+)
- **OpenSSL/Libssl-dev**: Cryptographic libraries
- **Build Essentials**: C compiler, make, pkg-config

### Infrastructure Requirements
- **DigitalOcean Token**: For stealth VPS rotation
- **AI Backends**: Ollama, Claude CLI, Kimi, or OpenAI API
- **OSINT API Keys**: Chaos, Netlas, Shodan, etc.

## Development Commands

### Building
```bash
# Normal build (bug-bounty mode)
cargo build --release

# Full sovereign mode with all features
cargo build --release --features sovereign

# Development build with debug symbols
cargo build

# Check for compilation errors
cargo check
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test module
cargo test --test module_name

# Run with verbose output
cargo test -- --nocapture
```

### Code Quality
```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Check dependencies
cargo audit
```

### Database Operations
```bash
# Run migrations
sqlx migrate run

# Create new migration
sqlx migrate add migration_name

# Revert migration
sqlx migrate revert
```

### Docker Operations
```bash
# Build Docker image
docker build -t osintultimate .

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

## Tool Integration

### Security Tools (60+ integrated)
- **Reconnaissance**: Nmap, Subfinder, Amass, Assetfinder
- **Web Security**: Sqlmap, Nuclei, FFUF, Gobuster
- **Cloud Security**: ScoutSuite, CloudSploit, Pacu
- **Mobile Security**: MobSF, Jadx, Apktool
- **Network Security**: Masscan, ZGrab, RustScan

### AI Integration
- **Tier 0**: Ollama/Phi (local, high-speed inference)
- **Tier 1**: Claude Code, Kimi K2.6
- **Tier 2**: GPT-4 (complex tactical decision-making)
- **Token Optimization**: Wenyan token optimization system