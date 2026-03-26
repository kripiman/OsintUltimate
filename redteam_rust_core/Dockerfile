# =============================================================================
# OsintUltimate - Dockerfile Multi-Stage
# =============================================================================
# Stage 1: Builder — Compila el binario Rust con todas las dependencias de build.
# Stage 2: Runner  — Imagen mínima de producción con las herramientas necesarias.
#
# IMPORTANTE - Requerimientos especiales en runtime:
#   - nmap --privileged ó --cap-add=NET_RAW --cap-add=NET_ADMIN (para -sS / vuln_scan)
#   - UID 1000 por defecto; montar /output con los permisos adecuados
#   - Ver docs/DOCKER.md para ejemplos de ejecución completos
# =============================================================================

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# Instalar dependencias de build (pkg-config, openssl, libsqlite3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copiar manifiestos primero para cachear la capa de dependencias
COPY Cargo.toml Cargo.lock ./

# Crear un src/ vacío para que cargo fetch funcione sin el código fuente real
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs

# Pre-fetch de dependencias (cachea si Cargo.toml no cambia)
RUN cargo fetch

# Copiar código fuente real y compilar en modo release
COPY src ./src

RUN cargo build --release --locked \
    && strip target/release/redteam_rust_core

# ── Stage 2: Runner ────────────────────────────────────────────────────────────
# debian:bookworm-slim (~80 MB) en lugar de distroless porque el motor
# ejecuta herramientas externas (nmap, nuclei, sqlmap, etc.) como subprocesos.
FROM debian:bookworm-slim AS runner

LABEL maintainer="RedTeam Lab <architect@redteam.lab>" \
      org.opencontainers.image.title="OsintUltimate" \
      org.opencontainers.image.description="High-performance async Red Team assessment engine" \
      org.opencontainers.image.version="3.0" \
      org.opencontainers.image.source="https://github.com/kripiman/OsintUltimate"

# ── Dependencias de runtime ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Certificados TLS (reqwest usa rustls, pero algunos plugins los necesitan)
    ca-certificates \
    # DNS y red
    dnsutils \
    iputils-ping \
    # nmap: herramienta core para escaneo de puertos y vuln-scan
    nmap \
    # python3 para sqlmap, wapiti, commix, etc.
    python3 \
    python3-pip \
    python3-venv \
    # curl / wget para descarga de herramientas Go en tiempo de build opcional
    curl \
    wget \
    # Herramientas de soporte
    git \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Herramientas Go (nuclei, httpx, ffuf, subfinder, amass, katana, dnsx, naabu, uncover) ──
# Se descarga la última versión de cada binario desde GitHub Releases.
ARG GOARCH=amd64
ENV GOARCH=${GOARCH}

# nuclei — scanner de vulnerabilidades por plantillas
RUN curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s | tr '[:upper:]' '[:lower:]')_${GOARCH}.zip" \
    -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# httpx — HTTP prober
RUN curl -sSfL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(uname -s | tr '[:upper:]' '[:lower:]')_${GOARCH}.zip" \
    -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

# subfinder — subdomain enumeration
RUN curl -sSfL "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(uname -s | tr '[:upper:]' '[:lower:]')_${GOARCH}.zip" \
    -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

# naabu — port scanner (complementa nmap)
RUN curl -sSfL "https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_$(uname -s | tr '[:upper:]' '[:lower:]')_${GOARCH}.zip" \
    -o /tmp/naabu.zip \
    && unzip -q /tmp/naabu.zip naabu -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/naabu \
    && rm /tmp/naabu.zip

# ffuf — web fuzzer
RUN curl -sSfL "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(curl -sSfL https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name | tr -d v)_linux_amd64.tar.gz" \
    -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz

# sqlmap — python-based SQL injection tool
RUN pip3 install --no-cache-dir sqlmap --break-system-packages

# ── Herramientas Python opcionales (en venv para evitar conflictos) ────────────
RUN python3 -m venv /opt/tools-venv \
    && /opt/tools-venv/bin/pip install --no-cache-dir \
       wapiti3 \
       commix \
    && ln -s /opt/tools-venv/bin/wapiti /usr/local/bin/wapiti \
    && ln -s /opt/tools-venv/bin/commix /usr/local/bin/commix

# ── Copiar binario compilado ──────────────────────────────────────────────────
COPY --from=builder /build/target/release/redteam_rust_core /usr/local/bin/osintultimate

# ── Configuración de usuario no-root ─────────────────────────────────────────
# EXCEPCIÓN: nmap -sS y --vuln-scan requieren CAP_NET_RAW.
# En ese caso, lanzar con: docker run --cap-add=NET_RAW --cap-add=NET_ADMIN
# o simplemente con: docker run --privileged (solo en entornos controlados de red team)
RUN groupadd -r redteam && useradd -r -g redteam -u 1000 redteam

# Directorio de trabajo y outputs
RUN mkdir -p /workspace /output && chown -R redteam:redteam /workspace /output

WORKDIR /workspace

# Por defecto corremos como usuario no-root.
# Para scans que requieren privilegios, sobreescribir con --user root ó --privileged.
USER redteam

# Volúmenes recomendados
VOLUME ["/workspace", "/output"]

# Exponer el endpoint OTEL si se usa
EXPOSE 4317

# Entrypoint
ENTRYPOINT ["/usr/local/bin/osintultimate"]

# Comando por defecto: mostrar ayuda
CMD ["--help"]
