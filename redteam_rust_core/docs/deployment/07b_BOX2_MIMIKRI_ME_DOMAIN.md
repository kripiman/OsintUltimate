# 07b — Box2: Dashboard Access via mimikri.me (Cloudflare Tunnel)

**Goal**: Expose `mimikri.me` to the operator on the public internet without:
- Opening any inbound port on Box2
- Revealing Box2 public IP
- Hosting plain HTTP

**Tool**: Cloudflare Tunnel (`cloudflared`) — free tier, outbound-only connection from Box2 to Cloudflare edge.

**Prerequisites**: Cloudflare account, domain `mimikri.me` with Cloudflare nameservers, Box2 from `03_BOX2_COORDINATOR.md`.

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
2. **Subdomain**: (leave empty or use `www`), **Domain**: `mimikri.me`
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
- Rule: any request to `mimikri.me/api/*` more than 30/min from same IP → block 10 minutes
- Apply to all locations

---

## 3. Install `cloudflared` on Box2

Since Box2 is the Coordinator running the dashboard, install it there:

```bash
ssh opsec@mimikri-box2

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
# Opens browser; pick mimikri.me zone, accept

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
sudo -u cloudflared cloudflared tunnel route dns mimikri-dashboard mimikri.me
# Creates CNAME mimikri.me → <UUID>.cfargotunnel.com in Cloudflare DNS
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
  - hostname: mimikri.me
    service: http://localhost:8080         # dashboard binds loopback
    originRequest:
      connectTimeout: 30s
      tlsTimeout: 10s
      tcpKeepAlive: 30s
      noHappyEyeballs: false
      keepAliveConnections: 4
      keepAliveTimeout: 90s
      httpHostHeader: mimikri-box2
      # Path-level filtering at origin (defense in depth)
      disableChunkedEncoding: false
      proxyType: ""
      ipRules: []

  - service: http_status:404                 # catch-all
```

> [!IMPORTANT]
> The dashboard must listen on `127.0.0.1:8080` for `cloudflared` to reach it locally. If it currently binds only to `tailscale0`, configure it to also bind loopback or point `cloudflared` at the tailnet IP.

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

Cloudflare Tunnel is **outbound-only**. Box2 still has zero inbound from the public internet.

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

After Cloudflare Access auth, the user lands on the dashboard. The existing token mechanism at `/opt/mimikri-ai/workspace/logs/dashboard.token` remains the **inner** auth factor.

URL pattern: `https://mimikri.me/?token=<32-char-hex>`

Token rotation:
```bash
# Rotate weekly
ssh opsec@mimikri-box2 'sudo -u mimikri-ai rm /opt/mimikri-ai/workspace/logs/dashboard.token && sudo systemctl restart redteam-enrichment'
# Coordinator regenerates token on start
```

The operator retrieves the new token via SSH (over Tailscale only) and bookmarks the new URL.

---

## 7. Audit log integration

Cloudflare Access logs every login attempt. Export to Loki (which runs on Box3, but the pull script runs on Box2):

```bash
# Box2 cron, hourly
0 * * * * mimikri-ai /opt/mimikri-ai/bin/pull-cf-access-logs.sh > /var/log/mimikri-ai/cf-access.log 2>&1
```

`/opt/mimikri-ai/bin/pull-cf-access-logs.sh`:
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

# Promtail picks up journald entries with tag=cf-access and ships to Loki on Box3
```

Alert when:
- Login from country not in allowlist → critical
- Multiple failed logins in 5min → warning
- Login outside operator working hours → info

---

## 8. Verification

```bash
# Tunnel up
curl -fsSL https://mimikri.me/healthz
# Expected: 401 (Cloudflare Access challenge) — NOT 502 (origin down) or open access

# DNS resolves to Cloudflare
dig mimikri.me +short
# Expected: 104.x.x.x (Cloudflare anycast)

# Origin IP not in DNS
nslookup mimikri.me | grep -v "104\." | grep -E "^Address"
# Expected: empty

# Box2 public IP NOT exposed
curl -fsSL --resolve mimikri.me:443:<box2-public-ip> https://mimikri.me/
# Expected: connection refused (UFW blocks) OR TLS error (no cert on Box2)

# Tunnel metrics
curl -s http://localhost:2000/metrics | grep cloudflared_tunnel_total_requests
```

End-to-end test (browser):
1. Visit `https://mimikri.me`
2. Cloudflare Access challenge appears → enter operator email → OTP/WebAuthn
3. Dashboard loads
4. Enter dashboard token (from `/opt/mimikri-ai/workspace/logs/dashboard.token`)
5. Dashboard functionality available

---

## 9. Alternative: Tailscale Funnel (NOT recommended)

Tailscale offers Funnel for public exposure. Why we don't use it:
- Exposes the tailnet device's `*.ts.net` subdomain to public — name-leaks the tailnet
- No identity-aware proxy layer
- No WAF
- Cannot use a custom domain (`mimikri.me`)

Funnel is forbidden by ACL in `05_TAILSCALE_MESH.md §8`.

---

## 10. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Cloudflare Access "policy bypass" misconfigured | Anyone can access dashboard | Test in incognito with non-operator email — must be denied |
| `cloudflared` auto-update changes behavior | Unexpected outage | `--no-autoupdate` in service args (above) |
| Domain not on Cloudflare nameservers | DNS routing broken | Domain registrar → set NS to Cloudflare |
| Dashboard listens 0.0.0.0 | Reachable directly on Box2 public IP | UFW already blocks; double-check `ss -ltnp` |
| Cloudflare API token in shell history | Leak | Rotate; use vault always |
| WebAuthn not enrolled | OTP fallback used (weaker) | Force WebAuthn in policy after first login |
| Mixed content warnings | Tunnel terminates TLS but app links to http:// | Set `httpHostHeader: mimikri.me` and ensure dashboard generates relative URLs |
| Loki cannot reach Cloudflare API | Logs missing | Box2 outbound to `api.cloudflare.com` must be allowed |

Proceed to `09_INCIDENT_RESPONSE.md`.
