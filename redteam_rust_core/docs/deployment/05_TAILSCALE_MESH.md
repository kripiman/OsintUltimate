# 05 — Tailscale Cross-Tenancy Mesh + ACL Policy

Connects Box1, Box2, Box3 (3 distinct Oracle tenancies) + ephemeral DO droplets into a single zero-trust mesh. **Must be completed before role-specific runbooks (02/03/04).**

---

## 1. Tailnet provisioning

1. Sign up at https://login.tailscale.com with the operator email (use a hardware key for 2FA).
2. Create a new tailnet. Note the tailnet domain (e.g. `tail-XXXX.ts.net`).
3. Generate per-box auth keys at https://login.tailscale.com/admin/settings/keys:

| Key purpose | Tag | Ephemeral | Reusable | Expiry |
|---|---|---|---|---|
| Box1 install | `tag:redteam-control` | no | one-shot | 1h |
| Box2 install | `tag:redteam-control` | no | one-shot | 1h |
| Box3 install | `tag:redteam-control` | no | one-shot | 1h |
| DO droplet pool | `tag:redteam-worker` | **yes** | reusable | 90d |
| Operator workstation | `tag:operator` | no | one-shot | 1h |

> [!IMPORTANT]
> Worker auth-key MUST be ephemeral. Otherwise destroyed droplets leave stale machine entries in the tailnet, consuming the 100-device free tier and leaking historical scan correlation.

---

## 2. Install Tailscale on each box

Run on Box1, Box2, Box3 (replace `tskey-auth-...` with the appropriate one-shot key):

```bash
ssh opsec@box1

# Official install with verified signature
curl -fsSL https://tailscale.com/install.sh | sh

# Bring up with tag + key
sudo tailscale up \
  --auth-key=tskey-auth-XXXXXXXXXXXXX \
  --advertise-tags=tag:redteam-control \
  --hostname=mimikri-box1 \
  --accept-routes=false \
  --accept-dns=false \
  --ssh=false                       # we use OpenSSH, not Tailscale SSH

# Verify
tailscale ip -4
# e.g. 100.x.y.z

sudo tailscale status
```

Repeat for Box2 (`--hostname=mimikri-box2`) and Box3 (`--hostname=mimikri-box3`).

---

## 3. ACL policy (admin console)

Navigate to https://login.tailscale.com/admin/acls and replace with the following policy. Validate with the test simulator before saving.

```jsonc
{
  // Tag ownership: only operator can apply tags
  "tagOwners": {
    "tag:operator":         ["autogroup:admin"],
    "tag:redteam-control":  ["autogroup:admin"],
    "tag:redteam-worker":   ["autogroup:admin"]
  },

  // Default deny — explicit allow only
  "acls": [
    // Operator workstation → control plane (all ports, for admin)
    {
      "action": "accept",
      "src":    ["tag:operator"],
      "dst":    ["tag:redteam-control:*"]
    },

    // Control plane intra-cluster (Postgres, NATS, OTEL, replication)
    {
      "action": "accept",
      "src":    ["tag:redteam-control"],
      "dst":    [
        "tag:redteam-control:5432",   // Postgres
        "tag:redteam-control:4222",   // NATS client
        "tag:redteam-control:8222",   // NATS monitoring
        "tag:redteam-control:4317",   // OTEL gRPC
        "tag:redteam-control:3100",   // Loki push
        "tag:redteam-control:9090",   // Prometheus
        "tag:redteam-control:3000",   // Grafana (operator only - see next rule)
        "tag:redteam-control:8080",   // Dashboard (Cloudflare Tunnel terminates here)
        "tag:redteam-control:11434"   // Ollama (Box2 only)
      ]
    },

    // Workers (DO ephemeral) → Postgres queue + NATS only
    {
      "action": "accept",
      "src":    ["tag:redteam-worker"],
      "dst":    [
        "tag:redteam-control:5432",   // Postgres scan_queue + findings
        "tag:redteam-control:4222"    // NATS for swarm coordination
      ]
    },

    // Workers MUST NOT talk to operator or other workers
    // (default deny applies)

    // Allow Tailscale → public internet (for workers to scan targets)
    {
      "action": "accept",
      "src":    ["tag:redteam-worker"],
      "dst":    ["autogroup:internet:*"]
    }
  ],

  // SSH via Tailscale not used — block to reduce attack surface
  "ssh": [],

  // Test rules — run via console "Test access" tab on every change
  "tests": [
    {
      "src":    "tag:redteam-worker",
      "accept": ["tag:redteam-control:5432", "1.1.1.1:443"],
      "deny":   ["tag:redteam-control:22", "tag:redteam-control:3000", "tag:operator:22"]
    },
    {
      "src":    "tag:operator",
      "accept": ["tag:redteam-control:22", "tag:redteam-control:3000"],
      "deny":   ["tag:redteam-worker:22"]
    },
    {
      "src":    "tag:redteam-control",
      "accept": ["tag:redteam-control:5432"],
      "deny":   ["autogroup:internet:80"]
    }
  ],

  // No node attributes allow workers to advertise routes
  "nodeAttrs": [
    {
      "target": ["tag:redteam-worker"],
      "attr":   ["funnel"]                // explicitly forbid funnel on workers
    }
  ],

  // Disable IPv6 if you do not use it
  "disableIPv6": false
}
```

> [!WARNING]
> Save policy → wait 30 seconds → verify simulator results in the "Tests" tab. ALL tests must pass before applying. A misconfigured ACL can lock out the operator workstation.

---

## 4. UFW lockdown to Tailscale interface

Now that mesh is up, finalize UFW on each box. Run on Box1/2/3:

```bash
# Remove temporary public-IP SSH rule (from 01_BASE_HARDENING.md §5)
sudo ufw status numbered
# Identify the rule, e.g. "[ 5] Anywhere from <OPERATOR_HOME_IP>"
sudo ufw delete <rule_number>

# Allow SSH only on tailscale0
sudo ufw allow in on tailscale0 to any port 22 proto tcp comment 'ssh via tailscale'

# Reload + verify
sudo ufw reload
sudo ufw status verbose
```

**Test connectivity** from operator workstation:
```bash
# Operator on tailnet
tailscale up --auth-key=tskey-auth-OPERATOR --advertise-tags=tag:operator --hostname=workstation
ssh opsec@100.x.y.z       # use tailnet IP, not public IP
```

If SSH still works → Tailscale is functioning. **Confirm SSH on public IP NO LONGER works** (should be blocked by UFW now):
```bash
ssh opsec@<public-ip-box1>   # expected: connection refused / timeout
```

---

## 5. DNS — MagicDNS

Enable MagicDNS in admin console → DNS tab. Each box becomes resolvable by hostname:
- `mimikri-box1.tail-XXXX.ts.net`
- `mimikri-box2.tail-XXXX.ts.net`
- `mimikri-box3.tail-XXXX.ts.net`

Use these hostnames in `redteam_rust_core` configs (postgres URL, NATS URL, OTEL endpoint) for stability across IP changes.

```bash
# From any box
ping mimikri-box3.tail-XXXX.ts.net
```

---

## 6. DO droplet pre-shared auth key

The worker droplet bootstrap (`06_DO_EPHEMERAL_WORKERS.md`) injects a reusable ephemeral auth-key. Generate it once:

```
Tags: tag:redteam-worker
Reusable: yes
Ephemeral: YES
Expiration: 90 days
```

Add to the `secrets.env` bundle as `TAILSCALE_AUTH_KEY=...` (see `08_SECRETS_MANAGEMENT.md` §3.1). Rotate every 90 days from the operator workstation:

```bash
# On operator workstation, quarterly
NEW_KEY=$(curl -sX POST -H "Authorization: Bearer $TS_API_KEY" \
  https://api.tailscale.com/api/v2/tailnet/${TAILNET}/keys \
  -d '{"capabilities":{"devices":{"create":{"reusable":true,"ephemeral":true,"preauthorized":true,"tags":["tag:redteam-worker"]}}},"expirySeconds":7776000}' \
  | jq -r .key)

# Decrypt secrets.env, swap the line, re-encrypt
PLAIN=$(age --decrypt -i ~/.config/age/identities.txt secrets.env.age)
echo "$PLAIN" | sed "s|^TAILSCALE_AUTH_KEY=.*|TAILSCALE_AUTH_KEY=$NEW_KEY|" \
  | age -R infrastructure/recipients.txt -o secrets.env.age
git add secrets.env.age && git commit -S -m "secrets: rotate tailscale worker key $(date -u +%Y-Q%q)"

# Redistribute to all 3 boxes
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  scp secrets.env.age opsec@$b:/tmp/ && \
  ssh opsec@$b 'sudo install -o root -g mimikri -m 0640 /tmp/secrets.env.age /opt/mimikri/etc/secrets.env.age && rm /tmp/secrets.env.age'
  ./unlock-remote.sh "$b" mimikri
done
```

---

## 7. Connection health monitoring

`/etc/systemd/system/tailscale-health.service` on each box:

```ini
[Unit]
Description=Tailscale connectivity check
After=tailscaled.service

[Service]
Type=oneshot
ExecStart=/usr/bin/tailscale netcheck
ExecStartPost=/bin/bash -c 'tailscale status | grep -q "active" || (logger -t tailscale-health "DEGRADED: no active peers" && exit 1)'
StandardOutput=journal
```

```ini
# /etc/systemd/system/tailscale-health.timer
[Unit]
Description=Run tailscale health check every 5 minutes
[Timer]
OnUnitActiveSec=5min
Persistent=true
[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tailscale-health.timer
```

Alerts when control plane peers become unreachable. Forwarded via journald → Loki on Box3.

---

## 8. Funnel — DISABLED

Tailscale Funnel can expose internal services to the public internet. **Never enable on this deployment** — it bypasses Cloudflare Tunnel and may leak Box IP.

Enforced via ACL `nodeAttrs` rule (§3). Verify:
```bash
sudo tailscale funnel status 2>&1 | grep -i "funnel"
# Expected: "Funnel is not enabled" or denied by policy
```

---

## 9. Verification checklist

```bash
# All 3 boxes appear with correct tags
tailscale status
# Expected: mimikri-box1, mimikri-box2, mimikri-box3 with tag:redteam-control

# SSH only via tailnet (from operator workstation)
ssh opsec@mimikri-box1.tail-XXXX.ts.net   # OK
ssh opsec@<public-ip-box1>                # FAIL (refused)

# Cross-box reachability
ssh opsec@mimikri-box1 'ping -c2 mimikri-box3.tail-XXXX.ts.net'
# Expected: 2/2 packets

# Worker key works (test on a throwaway VM)
sudo tailscale up --auth-key=$WORKER_KEY --advertise-tags=tag:redteam-worker --ephemeral
sudo tailscale ip -4   # 100.x.y.z
# Then verify postgres reachable, ssh denied to control:
nc -vz mimikri-box1 5432    # OK
nc -vz mimikri-box1 22      # DENIED (ACL)
sudo tailscale logout
```

Take a snapshot of admin console ACL JSON; commit to `redteam_rust_core/infrastructure/tailscale_acl.jsonc` (sanitized: replace tailnet domain with placeholder).

---

## 10. Failure modes

| Failure | Symptom | Recovery |
|---|---|---|
| Tailscale control plane outage | Existing peer connections continue; new peers cannot join | Wait — service-side. Existing scans unaffected. |
| Auth key expired | New droplets fail to join tailnet | Rotate per §6 and re-encrypt `secrets.env.age` |
| ACL misconfiguration | Operator locked out | Revert via admin console history; emergency: enable Oracle public SSH (cloud-init) for one-time recovery |
| MagicDNS down | Hostname resolution fails | Use raw `100.x.y.z` IPs from `tailscale status` |
| Tailscale daemon crash | `tailscale0` interface disappears, UFW blocks all traffic | `sudo systemctl restart tailscaled`; monitored by tailscale-health.timer (§7) |

Proceed to `08_SECRETS_MANAGEMENT.md` once verification passes.
