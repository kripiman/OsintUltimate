# 05 — Box4: Interactsh OOB Server (Azure Africa VPS) ✅ Permanent

**Role**: Out-of-band (OOB) interaction capture server. Detects blind SSRF, blind XSS, blind command injection, DNS rebinding, and any callback that proves a vulnerability is real but produces no inline response. Workers inject interactsh payloads; Box4 captures callbacks; Box2 (coordinator) correlates results to findings.

> [!IMPORTANT]
> Interactsh **must** run on a dedicated, persistent VPS — never on ephemeral DO droplets (which are destroyed every 6h, causing you to miss callbacks that arrive days later). Oracle VMs cannot host it (AUP prohibits receiving target-originated traffic; port 53 frequently blocked). The Azure Student VPS is the correct substrate.

**Prerequisites**: `01_BASE_HARDENING.md` (adapted for Azure), `05_TAILSCALE_MESH.md` (Box4 joins the same tailnet), `08_SECRETS_MANAGEMENT.md` (INTERACTSH_TOKEN added to secrets bundle).

**Specs**: Azure Student VPS — 1GB RAM, 2 vCPU, Africa region. Always-free via Azure Student credit. No OCI services used here.

---

## 1. Why interactsh needs its own persistent node

| Scenario | Ephemeral DO droplet | Box4 (persistent) |
|---|---|---|
| Payload injected into CI pipeline | ❌ Callback arrives in 24h — droplet gone | ✅ Server alive, callback captured |
| DNS rebinding attack | ❌ No stable DNS authority | ✅ NS record points to Box4 IP |
| SMTP callback (email header injection) | ❌ No port 25 listener | ✅ SMTP listener persistent |
| Blind XSS fires when admin reviews report | ❌ Could be days later | ✅ Server always listening |
| Correlation to scan_id | ❌ No Postgres access after destruction | ✅ Box2 polls API, correlates live |

---

## 2. DNS configuration (required before installing)

Interactsh requires DNS authority over a subdomain. Configure at your domain registrar:

```dns
; Delegate oast.<your-domain> to Box4 as its own nameserver
ns1.<your-domain>.      A     <azure-africa-public-ip>
oast.<your-domain>.     NS    ns1.<your-domain>.
```

> [!NOTE]
> `ns1.<your-domain>` is a glue record — it resolves Box4's own IP. This lets interactsh serve DNS responses for `*.oast.<your-domain>` from Box4 itself. Without this NS delegation, DNS interactions will not be captured.

Verify propagation (wait up to 24h for global propagation):
```bash
dig NS oast.<your-domain> @8.8.8.8
# Expected: ns1.<your-domain>.
dig A ns1.<your-domain> @8.8.8.8
# Expected: <azure-africa-public-ip>
```

---

## 3. Azure NSG (Network Security Group) rules

Open these ports **inbound** in the Azure portal for Box4's NSG:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 53 | TCP + UDP | Any | DNS interaction capture |
| 80 | TCP | Any | HTTP interaction capture |
| 443 | TCP | Any | HTTPS interaction capture |
| 25 | TCP | Any | SMTP interaction capture (optional but recommended) |
| 1337 | TCP | Tailscale CIDR only (`100.64.0.0/10`) | interactsh REST API — Box2 polls this |
| 22 | TCP | Operator IP only | SSH maintenance (restrict source IP) |

> [!CAUTION]
> Port 1337 (interactsh API) must **not** be exposed to the internet. It carries your interaction log and the token. Restrict to Tailscale CIDR only (`100.64.0.0/10`) in the NSG rule. Box2 reaches it over the Tailscale mesh.

---

## 4. Base hardening (Azure-adapted)

Apply `01_BASE_HARDENING.md` with these differences:

```bash
# Azure uses 'azureuser' as default; create opsec user as in 01 §2
# Tailscale install: same as 01 §14 placeholder
# UFW — add interactsh-specific rules after base setup:
sudo ufw allow 53/tcp comment 'interactsh DNS'
sudo ufw allow 53/udp comment 'interactsh DNS'
sudo ufw allow 80/tcp comment 'interactsh HTTP'
sudo ufw allow 443/tcp comment 'interactsh HTTPS'
sudo ufw allow 25/tcp comment 'interactsh SMTP'
# Port 1337 only from tailnet:
sudo ufw allow in on tailscale0 to any port 1337 proto tcp comment 'interactsh API tailnet only'
sudo ufw reload
```

> [!NOTE]
> Azure has its own NSG layer above UFW. Both must allow the ports. NSG is the outer firewall; UFW is the inner. 1337 must be blocked in NSG (only Tailscale CIDR) AND only allowed on `tailscale0` in UFW.

---

## 5. Tailscale join

Box4 joins the same tailnet as Box1/Box2/Box3:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up \
  --auth-key=<tailscale-auth-key-from-08-secrets> \
  --hostname=mimikri-box4-interactsh \
  --advertise-tags=tag:redteam-infra \
  --accept-routes=false \
  --ssh=false

# Verify tailnet IP
tailscale ip -4
# Record this as BOX4_TAILSCALE_IP
```

Update Tailscale ACL (`05_TAILSCALE_MESH.md §3`) to allow Box2 → Box4:1337:
```jsonc
{
  "acls": [
    // existing rules...
    { "action": "accept", "src": ["tag:redteam-infra"], "dst": ["tag:redteam-infra:1337"] }
  ]
}
```

---

## 6. Install interactsh-server

```bash
# Download latest release
INTERACTSH_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/interactsh/releases/latest | jq -r .tag_name)
wget -q "https://github.com/projectdiscovery/interactsh/releases/download/${INTERACTSH_VERSION}/interactsh-server_linux_amd64.zip" \
  -O /tmp/interactsh-server.zip
sudo unzip -o /tmp/interactsh-server.zip interactsh-server -d /usr/local/bin/
sudo chmod 755 /usr/local/bin/interactsh-server
rm /tmp/interactsh-server.zip

# Verify
interactsh-server -version
```

---

## 7. systemd service

Create service user and directories:
```bash
sudo groupadd -r interactsh
sudo useradd -r -g interactsh -d /opt/interactsh -s /sbin/nologin -c "Interactsh OOB Server" interactsh
sudo install -d -o interactsh -g interactsh -m 0750 /opt/interactsh
sudo install -d -o interactsh -g interactsh -m 0750 /opt/interactsh/data
sudo install -d -o root -g adm -m 0750 /var/log/interactsh
```

`/etc/systemd/system/interactsh.service`:
```ini
[Unit]
Description=Interactsh OOB Interaction Server
After=network-online.target tailscaled.service
Wants=network-online.target
# Restart on failure — callbacks must never be missed
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=interactsh
Group=interactsh

# Secrets loaded from tmpfs (same unlock flow as other boxes, 08_SECRETS_MANAGEMENT.md §4.3)
EnvironmentFile=/run/mimikri/secrets.env

ExecStart=/usr/local/bin/interactsh-server \
  -domain oast.${INTERACTSH_DOMAIN} \
  -ip ${INTERACTSH_PUBLIC_IP} \
  -token ${INTERACTSH_TOKEN} \
  -https-port 443 \
  -http-port 80 \
  -dns-port 53 \
  -smtp-port 25 \
  -store /opt/interactsh/data \
  -loglevel info

Restart=always
RestartSec=10

# Allow binding to privileged ports (<1024)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/interactsh/data
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryMax=512M
CPUWeight=50

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now interactsh
sudo systemctl status interactsh
```

---

## 8. Token generation

The `INTERACTSH_TOKEN` is a shared secret between Box4 (server) and all clients (Box2 coordinator + DO workers). Generate once and add to `secrets.env`:

```bash
# Generate a strong token (on operator workstation)
openssl rand -hex 32
# Output: e.g., a3f1c8d7b2e9...  → this is your INTERACTSH_TOKEN
```

Add to `secrets.env` before re-encrypting with `age` (see `08_SECRETS_MANAGEMENT.md §3`):
```env
# === Box4 Interactsh ===
INTERACTSH_TOKEN=<output-of-openssl-rand>
INTERACTSH_URL=https://oast.<your-domain>
INTERACTSH_PUBLIC_IP=<azure-africa-public-ip>
INTERACTSH_DOMAIN=<your-domain>
```

---

## 9. How Box2 polls for callbacks

Box2 (coordinator) runs a periodic interactsh polling coroutine that:

1. Calls `GET https://oast.<your-domain>/poll?id=<correlation-id>&secret=<INTERACTSH_TOKEN>` over Tailscale
2. Receives pending interactions: `{protocol: "dns", remote_address: "1.2.3.4", raw_request: "...", timestamp: "..."}`
3. Matches `correlation-id` to a `scan_id` in Postgres `findings` table
4. Updates the finding: `oob_confirmed = true`, `oob_type = "dns"`, `oob_source_ip = "1.2.3.4"`
5. Triggers enrichment pipeline on Box1 (AI classification of the confirmed finding)
6. Auto-submit to HackerOne if severity threshold met

The correlation-id is embedded in the interactsh subdomain payload:
```
# Worker generates payload using interactsh-client:
c73f1a.<correlation-id>.oast.<your-domain>

# Target makes DNS request → Box4 captures:
{protocol: "dns", id: "c73f1a.<correlation-id>", remote: "target-ip"}

# Box2 maps: correlation-id → scan_queue.id → findings.target_host
```

> [!NOTE]
> The interactsh client library is available as a Go library (`github.com/projectdiscovery/interactsh/pkg/client`). The Rust worker calls it via a subprocess or a thin HTTP wrapper. The exact integration point is Sprint 10 scope.

---

## 10. Worker payload injection

DO ephemeral workers receive interactsh configuration via `secrets.env` (injected at cloud-init time by Box2):

```bash
# In cloud-init Environment= block (06_DO_EPHEMERAL_WORKERS.md §2):
Environment="INTERACTSH_URL=${INTERACTSH_URL}"
Environment="INTERACTSH_TOKEN=${INTERACTSH_TOKEN}"

# Worker uses interactsh-client binary to generate payloads:
interactsh-client \
  -server ${INTERACTSH_URL} \
  -token ${INTERACTSH_TOKEN} \
  -v
# Output: unique subdomain per session, e.g. c73f1abc.oast.<your-domain>
```

Workers pass this payload URL to scan plugins that support OOB (nuclei, custom SSRF probes, XSS hunters, header injection).

---

## 11. AIDE baseline

After interactsh is running stably, update AIDE baseline:
```bash
sudo aide --update && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

## 12. Verification

```bash
# 1. interactsh service running
systemctl is-active interactsh
# Expected: active

# 2. DNS port listening
ss -ulnp | grep :53
# Expected: interactsh process on 0.0.0.0:53

# 3. HTTP/HTTPS ports listening
ss -tlnp | grep -E ':80|:443|:25|:1337'
# Expected: all 4 ports

# 4. DNS resolution (from operator workstation, after NS propagation)
dig A <random>.oast.<your-domain> @<azure-africa-public-ip>
# Expected: <azure-africa-public-ip> (wildcard response)

# 5. HTTP interaction capture (from operator workstation)
curl -fsSL http://<random>.oast.<your-domain>/test
# Box4 should log this interaction

# 6. Poll from Box2 (via Tailscale)
ssh opsec@mimikri-box2
curl -fsSL "https://oast.<your-domain>/poll?id=test&secret=${INTERACTSH_TOKEN}" | jq
# Expected: {data: [...interactions...]}

# 7. SMTP test (optional)
swaks --to test@<random>.oast.<your-domain> --server <azure-africa-public-ip>
# Expected: SMTP interaction captured on Box4

# 8. End-to-end: worker → Box4 → Box2 correlation (Sprint 10 integration test)
# See 10_SMOKE_TEST.md §5
```

---

## 13. Day-350 graduation gate

Box4 is on Azure Student credit. When the credit approaches expiry:

```bash
# Check Azure credit balance
az billing account show --query "currentSpend" -o table

# interactsh-server stores all interaction data locally in /opt/interactsh/data
# Archive before credit expiry:
tar -czf ~/interactsh-archive-$(date +%F).tar.gz /opt/interactsh/data
age -R recipients.txt -o interactsh-archive-$(date +%F).tar.gz.age \
  interactsh-archive-$(date +%F).tar.gz

# Options after Azure credit exhaustion:
# A) Migrate to a DO droplet (pay ~$6/mo, stable IP via Reserved IP)
# B) Self-host on Box2 or Box3 (acceptable if Azure gone — Oracle AUP allows
#    receiving callbacks from authorized bug bounty platforms)
# C) Use projectdiscovery.io hosted interactsh (free tier, but they see your callbacks)
```

> [!WARNING]
> If Azure Student email is also a university email subject to revocation: same risk as Box1. Consider migrating interactsh to a non-university account (personal Azure, a DO reserved IP, or Hetzner) before graduation.

---

## 14. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| NS record not propagated | `dig NS oast.<domain>` returns nothing | Wait 24-48h; check registrar TTL set to 300 |
| Azure NSG blocks port 53 | DNS callbacks not captured | Add inbound rule for 53/tcp+udp in NSG (separate from UFW) |
| `CAP_NET_BIND_SERVICE` missing | interactsh fails to bind port 53/80 | Verify `AmbientCapabilities=CAP_NET_BIND_SERVICE` in service file |
| Port 1337 exposed publicly | Token leaked, attacker reads your OOB data | NSG: restrict 1337 to `100.64.0.0/10` (Tailscale CIDR) only |
| Token mismatch between server and worker | Poll returns 401 | Verify `INTERACTSH_TOKEN` same in `secrets.env` on Box2 and Box4 |
| interactsh data dir fills disk | Service crashes after weeks | Set log rotation or cron to prune `/opt/interactsh/data` older than 90 days |
| SMTP port 25 blocked by Azure | SMTP callbacks missed | Azure blocks port 25 outbound by default on student VMs; inbound is separate — test with `swaks` |
| Worker generates payload but Box2 never polls | OOB confirmed silently lost | Verify Box2 polling coroutine active: `journalctl -u redteam-coordinator \| grep interactsh` |

Proceed to `06_DO_EPHEMERAL_WORKERS.md` (updated to inject interactsh config into workers).
