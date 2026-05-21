# 07 — Dashboard Public Access via Cloudflare Tunnel

**Goal**: Expose `mimikri.<tld>` to operator on the public internet without:
- Opening any inbound port on Box1
- Revealing Box1 public IP
- Hosting plain HTTP

**Tool**: Cloudflare Tunnel (`cloudflared`) — free tier, outbound-only connection from Box1 to Cloudflare edge.

**Prerequisites**: Cloudflare account, domain `mimikri.<tld>` with Cloudflare nameservers, Box1 from `02_BOX1_COORDINATOR.md`.

---

## 1. Threat model for public access

Exposing the dashboard publicly adds risk vs Tailscale-only access. Mitigations applied:
- **Identity-aware proxy**: Cloudflare Zero Trust Access (free for ≤50 users) gates the dashboard behind operator SSO + hardware MFA
- **No origin IP exposure**: Cloudflare edge IPs are the only public face
- **WAF**: Cloudflare's managed rulesets block obvious abuse (free tier includes baseline OWASP)
- **Rate limiting**: 30 req/min per IP, free tier
- **TLS termination at edge**: Cloudflare presents valid cert; backhaul uses Cloudflare-encrypted tunnel
- **App-layer auth**: Existing `dashboard.token` is a second factor inside the app
- **Audit log**: All Cloudflare Access logins recorded, exported to Loki via API

---

## 2. Cloudflare Zero Trust setup

### 2.1 Sign in to Cloudflare Zero Trust

https://one.dash.cloudflare.com → create a team if first time. Team name: `mimikri`. Free plan supports up to 50 users.

### 2.2 Configure identity provider

Recommended: use Cloudflare's built-in OTP-via-email + a SAML provider. For one-operator deploy, OTP is sufficient. For multi-operator, integrate GitHub or Google SSO.

1. **Settings → Authentication → Add new login method**
2. Select **One-time PIN** + **GitHub** (or Google)
3. Test login with operator email

### 2.3 Define Access Policy for dashboard

1. **Access → Applications → Add Application → Self-hosted**
2. **Subdomain**: `mimikri`, **Domain**: `<tld>`
3. **Session duration**: 8 hours
4. **Identity providers**: One-time PIN, GitHub
5. **Policies**:
   - Name: `operator-only`
   - Action: Allow
   - Rules: `Emails` is `operator@your.tld`
   - **Require**: Country = `<your country>`, Authentication method = `swk` (WebAuthn) — requires YubiKey on login

Save.

> [!IMPORTANT]
> If you skip the WebAuthn requirement, an attacker with phishing access to the operator email can log in via OTP. WebAuthn (YubiKey) mitigates this.

### 2.4 Add OWASP managed rules

**Security → WAF → Managed rules → Cloudflare Managed Ruleset + OWASP Core Ruleset**. Sensitivity: medium. Action for matches: block.

### 2.5 Rate limiting

**Security → WAF → Rate limiting rules**:
- Rule: any request to `mimikri.<tld>/api/*` more than 30/min from same IP → block 10 minutes
- Apply to all locations

---

## 3. Install `cloudflared` on Box1

```bash
ssh opsec@mimikri-box1

# Install via apt
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | sudo tee /usr/share/keyrings/cloudflare-main.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update
sudo apt install -y cloudflared

cloudflared --version
```

---

## 4. Authenticate + create tunnel

```bash
# As opsec, run interactive auth (one-time)
cloudflared tunnel login
# Opens browser; pick mimikri.<tld> zone, accept

# Tunnel created locally, credentials in ~/.cloudflared/cert.pem
sudo install -d -o cloudflared -g cloudflared -m 0750 /etc/cloudflared
sudo mv ~/.cloudflared/cert.pem /etc/cloudflared/cert.pem
sudo chown cloudflared:cloudflared /etc/cloudflared/cert.pem
sudo chmod 600 /etc/cloudflared/cert.pem
```

### 4.1 Create the tunnel

```bash
sudo -u cloudflared cloudflared tunnel create mimikri-dashboard
# Output:
#   Tunnel credentials written to /etc/cloudflared/<UUID>.json
#   Created tunnel mimikri-dashboard with id <UUID>

TUNNEL_UUID=<UUID-from-output>
```

### 4.2 Route DNS

```bash
sudo -u cloudflared cloudflared tunnel route dns mimikri-dashboard mimikri.<tld>
# Creates CNAME mimikri → <UUID>.cfargotunnel.com in Cloudflare DNS
```

### 4.3 Tunnel config

`/etc/cloudflared/config.yml`:

```yaml
tunnel: <UUID>
credentials-file: /etc/cloudflared/<UUID>.json
metrics: 127.0.0.1:2000           # internal metrics endpoint

# Outbound only — never accepts inbound
warp-routing:
  enabled: false

ingress:
  - hostname: mimikri.<tld>
    service: http://localhost:8080         # dashboard binds loopback + tailscale0
    originRequest:
      connectTimeout: 30s
      tlsTimeout: 10s
      tcpKeepAlive: 30s
      noHappyEyeballs: false
      keepAliveConnections: 4
      keepAliveTimeout: 90s
      httpHostHeader: mimikri-box1
      # Path-level filtering at origin (defense in depth)
      disableChunkedEncoding: false
      proxyType: ""
      ipRules: []

  - service: http_status:404                 # catch-all
```

> [!IMPORTANT]
> The dashboard must listen on `127.0.0.1:8080` for `cloudflared` to reach it locally. If it currently binds only to `tailscale0`, either:
> 1. Configure it to also bind loopback (modify `redteam_rust_core` dashboard listener)
> 2. Or point `cloudflared` at the tailnet IP: `service: http://100.x.x.x:8080`
>
> Option 2 is simpler; use it.

### 4.4 Systemd service

```bash
sudo cloudflared service install
# Creates /etc/systemd/system/cloudflared.service automatically

# Override with sandboxing
sudo systemctl edit cloudflared
```

Drop-in `/etc/systemd/system/cloudflared.service.d/override.conf`:

```ini
[Service]
User=cloudflared
Group=cloudflared
ExecStart=
ExecStart=/usr/bin/cloudflared --config /etc/cloudflared/config.yml --no-autoupdate tunnel run mimikri-dashboard

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ReadOnlyPaths=/etc/cloudflared
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @cpu-emulation @keyring @obsolete @raw-io @reboot @swap @privileged

MemoryMax=200M
CPUWeight=50
TasksMax=64
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflared
sudo systemctl status cloudflared
```

---

## 5. UFW — keep public ports closed

Cloudflare Tunnel is **outbound-only**. Box1 still has zero inbound from the public internet.

```bash
# Confirm no public exposure
sudo ufw status verbose
# Inbound rules: only `in on tailscale0` ALLOW; everything else default-deny.

# Cloudflared outbound: just standard HTTPS
sudo ufw allow out 443/tcp comment 'cloudflared egress'  # already allowed
sudo ufw allow out 7844 comment 'cloudflared optional QUIC'  # if QUIC fallback used
```

---

## 6. Defense-in-depth: dashboard token still required

After Cloudflare Access auth, the user lands on the dashboard. The existing token mechanism at `/opt/mimikri/workspace/logs/dashboard.token` remains the **inner** auth factor.

URL pattern: `https://mimikri.<tld>/?token=<32-char-hex>`

Token rotation:
```bash
# Rotate weekly
ssh opsec@mimikri-box1 'sudo -u mimikri rm /opt/mimikri/workspace/logs/dashboard.token && sudo systemctl restart redteam-coordinator'
# Coordinator regenerates token on start
```

The operator retrieves the new token via SSH (over Tailscale only) and bookmarks the new URL.

---

## 7. Audit log integration

Cloudflare Access logs every login attempt. Export to Loki:

```bash
# Box1 cron, hourly
0 * * * * mimikri /opt/mimikri/bin/pull-cf-access-logs.sh > /var/log/mimikri/cf-access.log 2>&1
```

`/opt/mimikri/bin/pull-cf-access-logs.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
# Secrets pre-loaded into /run/mimikri/secrets.env by operator unlock flow (08 §4.3)
. /run/mimikri/secrets.env

# Cloudflare API token must be in vault with Access:Read permission
SINCE=$(date -u -d '1 hour ago' --iso-8601=seconds)
UNTIL=$(date -u --iso-8601=seconds)

curl -fsSL \
  "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/access/logs/access_requests?since=${SINCE}&until=${UNTIL}" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  | jq -c '.result[]' \
  | while read -r line; do
      logger -t cf-access "$line"
    done

# Promtail picks up journald entries with tag=cf-access and ships to Loki
```

Grafana dashboard: `08-cloudflare-access.json` (commit to `infrastructure/grafana/`).

Alert when:
- Login from country not in allowlist → critical
- Multiple failed logins in 5min → warning
- Login outside operator working hours → info

---

## 8. Verification

```bash
# Tunnel up
curl -fsSL https://mimikri.<tld>/healthz
# Expected: 401 (Cloudflare Access challenge) — NOT 502 (origin down) or open access

# DNS resolves to Cloudflare
dig mimikri.<tld> +short
# Expected: 104.x.x.x (Cloudflare anycast)

# Origin IP not in DNS
nslookup mimikri.<tld> | grep -v "104\." | grep -E "^Address"
# Expected: empty

# Box1 public IP NOT exposed
curl -fsSL --resolve mimikri.<tld>:443:<box1-public-ip> https://mimikri.<tld>/
# Expected: connection refused (UFW blocks) OR TLS error (no cert on Box1)

# Tunnel metrics
curl -s http://localhost:2000/metrics | grep cloudflared_tunnel_total_requests
```

End-to-end test (browser):
1. Visit `https://mimikri.<tld>`
2. Cloudflare Access challenge appears → enter operator email → OTP/WebAuthn
3. Dashboard loads
4. Enter dashboard token (from `/opt/mimikri/workspace/logs/dashboard.token`)
5. ROI / Findings / Mission Injection tabs functional

---

## 9. Alternative: Tailscale Funnel (NOT recommended)

Tailscale offers Funnel for public exposure. Why we don't use it:
- Exposes the tailnet device's `*.ts.net` subdomain to public — name-leaks the tailnet
- No identity-aware proxy layer
- No WAF
- Cannot use a custom domain (`mimikri.<tld>`)

Funnel is forbidden by ACL in `05_TAILSCALE_MESH.md §8`.

---

## 10. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Cloudflare Access "policy bypass" misconfigured | Anyone can access dashboard | Test in incognito with non-operator email — must be denied |
| `cloudflared` auto-update changes behavior | Unexpected outage | `--no-autoupdate` in service args (above) |
| Domain not on Cloudflare nameservers | DNS routing broken | Domain registrar → set NS to Cloudflare |
| Dashboard listens 0.0.0.0 | Reachable directly on Box1 public IP | UFW already blocks; double-check `ss -ltnp` |
| Cloudflare API token in shell history | Leak | Rotate; use vault always |
| WebAuthn not enrolled | OTP fallback used (weaker) | Force WebAuthn in policy after first login |
| Mixed content warnings | Tunnel terminates TLS but app links to http:// | Set `httpHostHeader: mimikri.<tld>` and ensure dashboard generates relative URLs |
| Loki cannot reach Cloudflare API | Logs missing | Box1 outbound to `api.cloudflare.com` must be allowed |

Proceed to `09_INCIDENT_RESPONSE.md`.
