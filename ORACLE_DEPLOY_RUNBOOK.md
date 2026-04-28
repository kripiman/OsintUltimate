# OsintUltimate — Oracle Cloud ARM Production Runbook
**Target**: Ubuntu 24.04 · ARM64 (Ampere A1, 24 GB RAM) · `tu_dominio.com`  
**Versión arquitectura**: V14.3 Sovereign Swarm Hardened + Tailscale OPSEC  
**Dashboard**: Axum bind `127.0.0.1:8080` → Nginx → HTTPS solo via **red Tailscale WireGuard**

```
[Tu laptop]──WireGuard (Tailscale)──[Oracle ARM] ← único acceso al dashboard
                                         │
                                    [DO Egress nodes] ← escaneos salen aquí
```

> [!IMPORTANT]
> Reemplaza **`tu_dominio.com`**, **`TU_IP_ORACLE`** y **`TU_TAILNET`** en cada bloque antes de ejecutar.  
> El puerto 443 **nunca se abre** a internet. Solo SSH (22) y WireGuard (UDP 41641).  
> Ejecuta todos los comandos como el usuario de despliegue (`osint`) salvo donde se indique `sudo`.

---

## 0. Variables globales (exportar antes de empezar)

```bash
export DOMAIN="tu_dominio.com"          # Tu dominio público (para cert ACME)
export DASHBOARD_PORT="8080"            # Puerto interno del dashboard Axum
export MCP_PORT="3001"                  # Puerto interno MCP SSE
export DEPLOY_USER="osint"              # Usuario de despliegue (sin root)
export APP_DIR="/home/osint/osint-ultimate"
export CERT_EMAIL="tu@email.com"
export TAILNET="tu-tailnet.ts.net"      # Tu Tailnet (ver: tailscale status)
# TAILSCALE_IP se obtiene en §12 tras instalar tailscale
# export TAILSCALE_IP="100.x.x.x"      # Rellenar después de: tailscale ip -4
```

---

## 1. Hardening inicial del servidor

### 1.1 Actualizar sistema y crear usuario de despliegue

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git unzip build-essential pkg-config \
     libssl-dev ca-certificates gnupg lsb-release

# Crear usuario sin privilegios de root
sudo useradd -m -s /bin/bash $DEPLOY_USER
sudo usermod -aG docker $DEPLOY_USER

# Copiar tu clave SSH al nuevo usuario
sudo mkdir -p /home/$DEPLOY_USER/.ssh
sudo cp ~/.ssh/authorized_keys /home/$DEPLOY_USER/.ssh/
sudo chown -R $DEPLOY_USER:$DEPLOY_USER /home/$DEPLOY_USER/.ssh
sudo chmod 700 /home/$DEPLOY_USER/.ssh
sudo chmod 600 /home/$DEPLOY_USER/.ssh/authorized_keys
```

### 1.2 Hardening SSH

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardened.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers osint
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
Protocol 2
EOF

sudo systemctl restart sshd
```

> [!CAUTION]
> Verifica que puedes conectarte como `osint` con clave antes de cerrar la sesión actual.

### 1.3 Firewall UFW — principio fail-closed (Tailscale edition)

> [!NOTE]
> Con Tailscale **no abrimos el 443 a internet**. El 443 solo escucha en la interfaz `tailscale0` (100.x.x.x). Cualquier intento de acceso desde internet al dashboard — imposible.

```bash
sudo apt install -y ufw

sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH — solo desde tu IP pública (cámbiala por la tuya)
sudo ufw allow 22/tcp comment "SSH"

# HTTP público — solo para ACME challenge (Let's Encrypt cert del dominio)
sudo ufw allow 80/tcp comment "HTTP ACME challenge"

# Tailscale WireGuard — necesita UDP de entrada para NAT traversal
sudo ufw allow 41641/udp comment "Tailscale WireGuard"

# HTTPS dashboard — SOLO en interfaz tailscale0 (se aplica tras instalar Tailscale en §12)
# sudo ufw allow in on tailscale0 to any port 443 proto tcp comment "Dashboard Tailscale only"
# (Descomentar y ejecutar después de §12)

sudo ufw --force enable
sudo ufw status verbose
```

### 1.4 Sysctl network hardening

```bash
sudo tee /etc/sysctl.d/99-osint-hardening.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
vm.swappiness = 10
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
EOF

sudo sysctl -p /etc/sysctl.d/99-osint-hardening.conf
```

### 1.5 Fail2ban

```bash
sudo apt install -y fail2ban

sudo tee /etc/fail2ban/jail.d/99-osint.conf << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
bantime = 600
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status
```

---

## 2. Docker y PostgreSQL

### 2.1 Instalar Docker en ARM64

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker
sudo usermod -aG docker $DEPLOY_USER
newgrp docker
```

### 2.2 Transferir el repo y levantar PostgreSQL

```bash
# Desde tu máquina local:
rsync -avz --exclude='.git' --exclude='target/' \
    /home/kripi/Documentos/GitHub/OsintUltimate/ \
    osint@TU_IP_ORACLE:$APP_DIR/

# En el servidor — editar password ANTES de levantar:
nano $APP_DIR/docker-compose.db.yml
# Cambia: WENYANULTRA_SECURE_PASS → una contraseña real fuerte
# Y actualiza DATABASE_URL en .env.oracle en sync

cd $APP_DIR
docker compose -f docker-compose.db.yml up -d
docker compose -f docker-compose.db.yml ps
```

### 2.3 Verificar PostgreSQL

```bash
docker exec -it osint_postgres psql -U osintuser -d osintdb -c "\dt"
```

---

## 3. Rust y compilación ARM64

### 3.1 Instalar Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup update stable
```

### 3.2 Dependencias del sistema

```bash
sudo apt install -y \
    libpq-dev libsqlite3-dev libpcap-dev \
    nmap masscan cmake clang
```

### 3.3 Compilar

```bash
cd $APP_DIR/redteam_rust_core
export DATABASE_URL="$(grep DATABASE_URL $APP_DIR/.env.oracle | cut -d= -f2-)"
cargo build --release
```

### 3.4 Migraciones PostgreSQL

```bash
cargo install sqlx-cli --no-default-features --features postgres

sqlx migrate run \
    --database-url "$DATABASE_URL" \
    --source $APP_DIR/redteam_rust_core/migrations

docker exec -it osint_postgres psql -U osintuser -d osintdb -c "\dt"
```

---

## 4. Nginx — Reverse Proxy + SSL

### 4.1 Instalar Nginx y Certbot

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable --now nginx
```

### 4.2 Config HTTP temporal (ACME challenge)

```bash
sudo tee /etc/nginx/sites-available/osint-ultimate << EOF
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF

sudo ln -sf /etc/nginx/sites-available/osint-ultimate /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

### 4.3 Obtener certificado SSL

```bash
sudo certbot certonly \
    --nginx \
    --non-interactive \
    --agree-tos \
    --email $CERT_EMAIL \
    -d $DOMAIN

sudo ls -la /etc/letsencrypt/live/$DOMAIN/
```

### 4.4 Configuración Nginx con TLS + SSE + binding en Tailscale

> [!IMPORTANT]
> **Ejecutar §12 (Tailscale) primero.** Este bloque necesita `$TAILSCALE_IP` ya poblado.
> El servidor HTTPS escucha **solo en la IP de Tailscale** (`100.x.x.x:443`), no en `0.0.0.0`.
> Desde internet, el puerto 443 de Oracle es invisible.

```bash
# Verificar que TAILSCALE_IP está definida
echo "Tailscale IP: $TAILSCALE_IP"
[ -z "$TAILSCALE_IP" ] && echo "ERROR: ejecuta primero §12" && exit 1

# Obtener certificado Tailscale (válido para MACHINE.ts.net)
# No necesita certbot ni port 80 abierto — Tailscale CA firma internamente
sudo tailscale cert --cert-file /etc/ssl/tailscale/cert.pem \
                    --key-file  /etc/ssl/tailscale/key.pem \
                    $(tailscale status --json | python3 -c \
                    "import json,sys; d=json.load(sys.stdin); print(d['Self']['DNSName'].rstrip('.'))")
sudo mkdir -p /etc/ssl/tailscale
sudo chmod 750 /etc/ssl/tailscale
sudo chown root:www-data /etc/ssl/tailscale

# Nombre DNS del nodo Tailscale (ej: oracle-arm.tu-tailnet.ts.net)
export TS_HOSTNAME=$(tailscale status --json | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(d['Self']['DNSName'].rstrip('.'))")
echo "Tailscale hostname: $TS_HOSTNAME"

# Generar cert desde Tailscale CA (cubre el hostname MagicDNS)
sudo mkdir -p /etc/ssl/tailscale
sudo tailscale cert \
    --cert-file /etc/ssl/tailscale/fullchain.pem \
    --key-file  /etc/ssl/tailscale/privkey.pem \
    "$TS_HOSTNAME"
sudo chown -R root:www-data /etc/ssl/tailscale
sudo chmod 640 /etc/ssl/tailscale/*.pem
```

```bash
# Configurar Nginx — listener en Tailscale IP únicamente
sudo tee /etc/nginx/sites-available/osint-ultimate << 'NGINXEOF'
limit_req_zone $binary_remote_addr zone=dashboard:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=120r/m;
limit_req_zone $binary_remote_addr zone=stream:10m rate=10r/m;

# Puerto 80 solo para ACME challenge del dominio público (cert Let's Encrypt)
# Si no necesitas cert de dominio público, eliminar este bloque.
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 444; }   # Silenciar todo lo demás (no redirect)
}

# HTTPS — solo en la interfaz Tailscale (100.x.x.x)
# Accesible únicamente desde dispositivos en tu Tailnet
server {
    listen TAILSCALE_IP_PLACEHOLDER:443 ssl;
    http2 on;
    server_name TS_HOSTNAME_PLACEHOLDER DOMAIN_PLACEHOLDER;

    # Certificado firmado por Tailscale CA (válido en tu Tailnet)
    ssl_certificate     /etc/ssl/tailscale/fullchain.pem;
    ssl_certificate_key /etc/ssl/tailscale/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    access_log /var/log/nginx/osint-dashboard-access.log;
    error_log  /var/log/nginx/osint-dashboard-error.log warn;

    # Dashboard principal
    location / {
        limit_req zone=dashboard burst=20 nodelay;
        proxy_pass         http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }

    # API REST
    location /api/v1/ {
        limit_req zone=api burst=30 nodelay;
        proxy_pass         http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }

    location /api/v2/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass         http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }

    # SSE Stream — Server-Sent Events (findings/stream)
    # proxy_buffering off es CRÍTICO para SSE
    location /api/v1/findings/stream {
        limit_req zone=stream burst=5 nodelay;
        proxy_pass         http://127.0.0.1:PORT_PLACEHOLDER;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        chunked_transfer_encoding on;
    }

    # MCP SSE Server
    location /mcp/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass         http://127.0.0.1:MCP_PORT_PLACEHOLDER/;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_buffering    off;
        proxy_read_timeout 3600s;
    }
}
NGINXEOF

# Sustituir placeholders con valores reales
sudo sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /etc/nginx/sites-available/osint-ultimate
sudo sed -i "s/PORT_PLACEHOLDER/$DASHBOARD_PORT/g" /etc/nginx/sites-available/osint-ultimate
sudo sed -i "s/MCP_PORT_PLACEHOLDER/$MCP_PORT/g" /etc/nginx/sites-available/osint-ultimate
sudo sed -i "s/TAILSCALE_IP_PLACEHOLDER/$TAILSCALE_IP/g" /etc/nginx/sites-available/osint-ultimate
sudo sed -i "s/TS_HOSTNAME_PLACEHOLDER/$TS_HOSTNAME/g" /etc/nginx/sites-available/osint-ultimate

sudo ln -sf /etc/nginx/sites-available/osint-ultimate /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
echo "✅ Dashboard disponible en: https://$TS_HOSTNAME  (solo desde Tailnet)"
```

### 4.5 Habilitar UFW para Tailscale y cerrar 443 público

```bash
# Ahora que Tailscale está instalado, aplicar la regla UFW que faltaba
sudo ufw allow in on tailscale0 to any port 443 proto tcp comment "Dashboard Tailscale only"
sudo ufw allow in on tailscale0 to any port $MCP_PORT proto tcp comment "MCP Tailscale only"
# El 443 público NUNCA fue abierto — verificar:
sudo ufw status numbered | grep 443
# Solo debe aparecer la línea de tailscale0, no 0.0.0.0
```

### 4.6 Auto-renovación certificado Tailscale

```bash
# Tailscale cert se renueva automáticamente por el daemon.
# Crear un cron semanal para sincronizar los archivos con nginx:
(crontab -l 2>/dev/null; echo "0 3 * * 1 tailscale cert --cert-file /etc/ssl/tailscale/fullchain.pem --key-file /etc/ssl/tailscale/privkey.pem $TS_HOSTNAME && systemctl reload nginx") | sudo crontab -
```

---

## 5. Servicio systemd producción

```bash
sudo tee /etc/systemd/system/osint-ultimate.service << EOF
[Unit]
Description=OsintUltimate Autonomous Red-Team Engine V14.2
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=$DEPLOY_USER
WorkingDirectory=$APP_DIR/redteam_rust_core
EnvironmentFile=$APP_DIR/.env.oracle
ExecStart=$APP_DIR/redteam_rust_core/target/release/redteam_rust_core \
    --dashboard $DASHBOARD_PORT \
    --mcp-server \
    --mcp-port $MCP_PORT \
    --json-logs
Restart=always
RestartSec=10
TimeoutStopSec=15
NoNewPrivileges=yes
PrivateTmp=yes
LimitNOFILE=65535
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=osint-ultimate

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable osint-ultimate

# Preparar workspace
mkdir -p $APP_DIR/redteam_rust_core/workspace/{logs,reports,plugins}
mkdir -p $APP_DIR/backups
```

---

## 6. Herramientas BlackArch y seguridad

### 6.1 BlackArch via Docker (recomendado en Oracle)

```bash
docker pull blackarchlinux/blackarch:latest

sudo tee /usr/local/bin/barch << 'EOF'
#!/bin/bash
# Wrapper BlackArch containerizado
TOOL="$1"; shift
docker run --rm -it --network host \
    -v "$(pwd):/workspace" -w /workspace \
    --cap-add NET_RAW --cap-add NET_ADMIN \
    blackarchlinux/blackarch "$TOOL" "$@"
EOF
sudo chmod +x /usr/local/bin/barch
```

### 6.2 Herramientas nativas ARM64

```bash
# Reconocimiento y scanning
sudo apt install -y nmap masscan whatweb dnsutils whois nikto \
    gobuster curl wget httpie

# Red y análisis
sudo apt install -y tcpdump tshark netcat-openbsd socat \
    traceroute mtr-tiny

# Web pentesting
sudo apt install -y sqlmap wfuzz hydra

# Proxy / SOCKS
sudo apt install -y dante-server proxychains4 tor

# Crypto / TLS
sudo apt install -y openssl sslscan

# OSINT
sudo apt install -y theharvester recon-ng exiftool

# Wordlists
sudo apt install -y wordlists
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
```

### 6.3 Herramientas Go (ProjectDiscovery stack)

```bash
wget -q https://go.dev/dl/go1.22.2.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.22.2.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/hakluke/hakrawler@latest

nuclei -update-templates
```

### 6.4 Herramientas Python

```bash
sudo apt install -y python3-pip pipx
pipx ensurepath

pipx install name-that-hash
pipx install wafw00f
pipx install droopescan
pipx install dnsrecon
pipx install dirsearch
pipx install shodan
```

### 6.5 Rust tools

```bash
cargo install feroxbuster
```

---

## 7. Dante SOCKS5 local (egreso interno)

```bash
sudo tee /etc/danted.conf << 'EOF'
logoutput: /var/log/danted.log
internal: 127.0.0.1 port = 1080
external: eth0
socksmethod: username
clientmethod: none
user.privileged: root
user.unprivileged: nobody
client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}
socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    protocol: tcp udp
    socksmethod: username
    log: error
}
EOF

sudo useradd -M -s /usr/sbin/nologin socks_local
echo "socks_local:$(openssl rand -hex 16)" | sudo chpasswd
sudo systemctl enable --now danted
```

---

## 8. Monitoreo y logrotate

### 8.1 Logrotate

```bash
sudo tee /etc/logrotate.d/osint-ultimate << 'EOF'
/home/osint/osint-ultimate/redteam_rust_core/workspace/logs/*.jsonl
/home/osint/osint-ultimate/redteam_rust_core/workspace/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 osint osint
    copytruncate
}
EOF
```

### 8.2 Healthcheck script + cron

```bash
mkdir -p $APP_DIR/scripts

cat > $APP_DIR/scripts/healthcheck.sh << SCRIPT
#!/bin/bash
DOMAIN="$DOMAIN"
LOG="$APP_DIR/healthcheck.log"
TS=\$(date '+%Y-%m-%d %H:%M:%S')

# PostgreSQL
docker exec osint_postgres pg_isready -U osintuser -d osintdb > /dev/null 2>&1 \
    && echo "[\$TS] PG: OK" >> \$LOG \
    || { echo "[\$TS] PG: FAIL" >> \$LOG; docker compose -f $APP_DIR/docker-compose.db.yml restart postgres; }

# Dashboard HTTPS
HTTP_CODE=\$(curl -sk -o /dev/null -w "%{http_code}" https://\$DOMAIN/api/v1/stats)
[ "\$HTTP_CODE" = "200" ] || [ "\$HTTP_CODE" = "401" ] \
    && echo "[\$TS] DASH: OK (\$HTTP_CODE)" >> \$LOG \
    || { echo "[\$TS] DASH: FAIL (\$HTTP_CODE)" >> \$LOG; systemctl restart osint-ultimate; }

# SSL cert expiry
EXPIRY=\$(echo | openssl s_client -connect \$DOMAIN:443 -servername \$DOMAIN 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
DAYS=\$(( ( \$(date -d "\$EXPIRY" +%s) - \$(date +%s) ) / 86400 ))
echo "[\$TS] SSL: \$DAYS days remaining" >> \$LOG
[ "\$DAYS" -lt 15 ] && echo "[\$TS] SSL WARNING: expires in \$DAYS days!" >> \$LOG
SCRIPT

chmod +x $APP_DIR/scripts/healthcheck.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * $APP_DIR/scripts/healthcheck.sh") | crontab -
```

---

## 9. Oracle Cloud VCN — Security Lists (Tailscale edition)

> [!IMPORTANT]
> Con Tailscale el perfil de VCN cambia radicalmente. **El puerto 443 NO aparece** en las reglas de ingreso. El dashboard es invisible desde internet.

Consola Oracle → **Networking → VCN → Security Lists → Default → Ingress Rules**:

| Protocolo | Puerto | Fuente | Descripción |
|-----------|--------|--------|-------------|
| TCP | 22 | `TU_IP_PUBLICA/32` | SSH — solo tu IP |
| TCP | 80 | `0.0.0.0/0` | HTTP ACME challenge (certbot dominio público) |
| UDP | 41641 | `0.0.0.0/0` | **Tailscale WireGuard** — NAT traversal |

> [!NOTE]
> Si Tailscale logra conectar por DERP relay sin el UDP directo (lo hace en la mayoría de casos), el 41641 tampoco es estrictamente necesario. Pero abrirlo mejora la latencia del túnel WireGuard.

**Reglas que NO existen (comparado con la configuración anterior):**
- ~~TCP 443 → 0.0.0.0/0~~ ← eliminado intencionalmente

**Egress**: Allow All.

---

## 10. Secuencia de Go-Live

Orden de dependencias: Tailscale → DB → Compile → Nginx → Engine

```bash
# 0. Tailscale (debe ejecutarse ANTES que Nginx — necesitamos TAILSCALE_IP)
export TAILSCALE_IP=$(tailscale ip -4)
export TS_HOSTNAME=$(tailscale status --json | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(d['Self']['DNSName'].rstrip('.'))")
echo "✅ Tailscale: $TAILSCALE_IP ($TS_HOSTNAME)"

# 1. PostgreSQL
cd $APP_DIR && docker compose -f docker-compose.db.yml up -d && sleep 5

# 2. Migraciones
export DATABASE_URL="$(grep DATABASE_URL $APP_DIR/.env.oracle | cut -d= -f2-)"
sqlx migrate run --database-url "$DATABASE_URL" --source $APP_DIR/redteam_rust_core/migrations

# 3. Cert Tailscale + Nginx
sudo tailscale cert \
    --cert-file /etc/ssl/tailscale/fullchain.pem \
    --key-file  /etc/ssl/tailscale/privkey.pem \
    "$TS_HOSTNAME"
sudo nginx -t && sudo systemctl reload nginx

# 4. Verificar que el dashboard NO responde desde internet
curl -sk --max-time 5 https://$DOMAIN/api/v1/stats && echo "WARN: accesible desde internet" || echo "✅ Invisible desde internet"

# 5. Verificar que SÍ responde desde Tailnet (ejecutar en tu laptop con Tailscale)
# curl -sk https://$TS_HOSTNAME/api/v1/stats

# 6. Iniciar engine
sudo systemctl start osint-ultimate && sleep 3
sudo systemctl status osint-ultimate

# 7. Leer token del dashboard
cat $APP_DIR/redteam_rust_core/workspace/logs/dashboard.token

# 8. Acceder al dashboard desde tu laptop (con Tailscale activo)
echo "Abre en tu navegador: https://$TS_HOSTNAME"
```

---

## 11. Referencia de comandos operacionales

```bash
# Control del servicio
sudo systemctl {start|stop|restart|status} osint-ultimate

# Logs en tiempo real
sudo journalctl -u osint-ultimate -f --output=cat

# Logs Nginx
sudo tail -f /var/log/nginx/osint-dashboard-{access,error}.log

# Kill-switch manual — destruir todos los droplets efímeros
curl -X DELETE "https://api.digitalocean.com/v2/droplets?tag_name=osint-ultimate" \
    -H "Authorization: Bearer $DIGITALOCEAN_TOKEN"

# Backup de base de datos
docker exec osint_postgres pg_dump -U osintuser osintdb \
    | gzip > $APP_DIR/backups/osintdb_$(date +%Y%m%d_%H%M%S).sql.gz

# Actualizar firmas nuclei
nuclei -update-templates

# Renovar SSL manualmente
sudo certbot renew && sudo systemctl reload nginx

# Grade SSL (ejecutar desde otra máquina)
curl -s "https://api.ssllabs.com/api/v3/analyze?host=$DOMAIN&startNew=on" \
    | python3 -m json.tool | grep grade

# Puertos abiertos (desde fuera)
nmap -sV --open $DOMAIN

# Estado Fail2ban
sudo fail2ban-client status sshd
```

---

## 12. Tailscale — Instalación y configuración OPSEC

> [!IMPORTANT]
> **Ejecutar esta sección ANTES que el bloque §4 (Nginx).** Nginx necesita `$TAILSCALE_IP`.

### 12.1 Instalar Tailscale en el servidor Oracle

```bash
# Instalación oficial — ARM64 nativo
curl -fsSL https://tailscale.com/install.sh | sh

# Activar y autenticar (abre la URL en tu navegador)
sudo tailscale up \
    --hostname="oracle-c2" \
    --advertise-tags="tag:server" \
    --ssh                         # Opcional: habilita Tailscale SSH (alternativa a OpenSSH)

# Ver IP asignada en tu Tailnet
tailscale ip -4      # → 100.x.x.x
tailscale status     # → debe mostrar oracle-c2 como Connected

# Exportar para usar en el resto del runbook
export TAILSCALE_IP=$(tailscale ip -4)
export TS_HOSTNAME=$(tailscale status --json | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(d['Self']['DNSName'].rstrip('.'))")
echo "IP Tailscale: $TAILSCALE_IP"
echo "Hostname:     $TS_HOSTNAME"
```

### 12.2 Instalar Tailscale en tu laptop de operaciones

```bash
# Linux
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# macOS
brew install tailscale
sudo tailscale up

# Windows
# Descargar desde: https://tailscale.com/download/windows
# Luego: tailscale up

# Verificar conexión con el servidor
tailscale ping oracle-c2
# → pong from oracle-c2 (100.x.x.x) via DERP[xxx] in XXms
```

### 12.3 Hardening de la Tailnet (consola admin)

En [https://login.tailscale.com/admin](https://login.tailscale.com/admin):

```
Settings → Access Controls (ACL) → Editar:
```

```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["autogroup:owner"],
      "dst": ["tag:server:443", "tag:server:8080", "tag:server:3001"]
    }
  ],
  "tagOwners": {
    "tag:server": ["autogroup:owner"]
  }
}
```

Esto garantiza que **solo el owner** de la Tailnet puede conectarse a los puertos del dashboard. Cualquier otro dispositivo en la red — denegado.

### 12.4 Configurar Tailscale como servicio persistente

```bash
# El instalador ya habilita tailscaled como servicio systemd
sudo systemctl status tailscaled    # debe mostrar: active (running)
sudo systemctl is-enabled tailscaled  # debe mostrar: enabled

# Si necesitas re-autenticar tras reboot sin intervención manual:
# Generar auth key en: https://login.tailscale.com/admin/settings/keys
# → Create auth key → Reusable + Ephemeral: NO → Copiar el key

sudo tailscale up \
    --auth-key=tskey-auth-XXXXXXXXX \
    --hostname="oracle-c2" \
    --advertise-tags="tag:server"
```

### 12.5 Generar certificado TLS desde Tailscale CA

```bash
# Tailscale emite certificados para tu nodo vía su propia CA (HTTPS cert)
# válido para: oracle-c2.TU-TAILNET.ts.net
sudo mkdir -p /etc/ssl/tailscale
sudo tailscale cert \
    --cert-file /etc/ssl/tailscale/fullchain.pem \
    --key-file  /etc/ssl/tailscale/privkey.pem \
    "$TS_HOSTNAME"

# Dar acceso a Nginx al cert
sudo chown -R root:www-data /etc/ssl/tailscale
sudo chmod 750 /etc/ssl/tailscale
sudo chmod 640 /etc/ssl/tailscale/*.pem

# Verificar cert
openssl x509 -in /etc/ssl/tailscale/fullchain.pem -noout -subject -dates
# → CN = oracle-c2.TU-TAILNET.ts.net
```

### 12.6 Verificación de aislamiento OPSEC

```bash
# Desde INTERNET (otra máquina sin Tailscale) — debe fallar/timeout:
curl -sk --max-time 5 https://TU_IP_ORACLE:443      # → timeout o connection refused ✅
curl -sk --max-time 5 https://$DOMAIN:443           # → solo ACME challenge en :80 funciona ✅

# Desde tu LAPTOP con Tailscale conectado — debe funcionar:
curl -sk https://$TS_HOSTNAME/api/v1/stats          # → {"status":...} o 401 ✅

# Fingerprint en Shodan — Oracle IP debe mostrar solo puerto 80 si ACME activo (o nada):
# nmap -sV TU_IP_ORACLE → solo puerto 22 y 80 (si ACME). Puerto 443: cerrado.

# Verificar Tailscale status en tiempo real
tailscale status
tailscale netcheck    # muestra latencia y ruta (DERP vs directo)
```

### 12.7 Arquitectura de red final

```
╔═══════════════════════════════════════════════════════════╗
║           OPSEC NETWORK MAP — V14.3 Tailscale             ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  [Tu Laptop]                    [Oracle ARM 24GB]         ║
║   tailscale0: 100.a.b.c ─────── tailscale0: 100.x.y.z    ║
║   WireGuard E2E encrypted ─────── Nginx :443 (solo LAN TS)║
║   Browser → https://oracle-c2.ts.net ──▶ Dashboard        ║
║                                         │                 ║
║  [Internet / Shodan]                    │                 ║
║   TU_IP_ORACLE:443 → CLOSED ✅          │                 ║
║   TU_IP_ORACLE:80  → ACME only         │                 ║
║   TU_IP_ORACLE:22  → Solo tu IP        │                 ║
║                                         ▼                 ║
║                              [DigitalOcean Droplets]       ║
║                               SOCKS5 Egress Nodes          ║
║                               Ephemeral + Auto-Destroy     ║
╚═══════════════════════════════════════════════════════════╝
```

---

*Generado: 2026-04-28 · OsintUltimate V14.3 Sovereign · Oracle ARM64 + Tailscale OPSEC + DO Egress*
