# =============================================================================
# OsintUltimate - Minimalist Sidecar Toolset (V4 Slim)
# =============================================================================
# Image optimized for Dynamic Hybrid Sandboxing.
# =============================================================================
FROM alpine:3.19 AS runner

LABEL org.opencontainers.image.title="OsintUltimate Tools (V4 Slim)" \
      org.opencontainers.image.description="Sidecar container for isolated tool execution"

# 1. Base Essentials (Ultra-Lightweight)
RUN apk add --no-cache \
    ca-certificates \
    nmap \
    python3 \
    py3-pip \
    jq \
    curl \
    libcap \
    libgcc \
    libstdc++

# 2. ProjectDiscovery Stack (Binary-only, no bloat)
ARG GOARCH=amd64
RUN for tool in nuclei httpx subfinder naabu; do \
      curl -sSfL "https://github.com/projectdiscovery/${tool}/releases/latest/download/${tool}_linux_${GOARCH}.zip" -o "/tmp/${tool}.zip" \
      && unzip -q "/tmp/${tool}.zip" -d /usr/local/bin/ "${tool}" \
      && chmod +x "/usr/local/bin/${tool}" \
      && rm "/tmp/${tool}.zip"; \
    done

# 3. Web Specialized (sqlmap, ffuf)
RUN pip3 install --no-cache-dir sqlmap --break-system-packages \
    && curl -sSfL "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(curl -sSfL https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name | tr -d v)_linux_amd64.tar.gz" \
    -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz

# 4. Security Hardening
RUN addgroup -S redteam && adduser -S redteam -G redteam -u 1000 \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /home/redteam
USER redteam

# Default command is built-in help
ENTRYPOINT ["/bin/sh", "-c"]
