# 10 — End-to-End Smoke Test

Validate the full hybrid deployment with a low-risk scan. Run after all 9 preceding runbooks complete.

**Target**: `scanme.nmap.org` (Nmap's authorized public test target — explicitly opt-in for scanning).
**Scope_id**: `smoke-test-2026`.
**Expected duration**: 30 minutes.

---

## 1. Pre-flight

```bash
# Secrets unlocked on every box (tmpfs present)
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  ssh opsec@$b 'sudo test -f /run/mimikri/secrets.env && echo "$(hostname): unlocked" || echo "$(hostname): LOCKED — run unlock-remote.sh first"'
done
# Expected: all three "unlocked"

# All 3 boxes healthy
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  echo "=== $b ==="
  ssh opsec@$b 'systemctl is-active redteam-* postgresql ollama tailscaled cloudflared 2>&1 | head -10'
done

# Tailnet
tailscale status
# Expected: all 3 boxes online

# Cloudflare tunnel
curl -fsSL -o /dev/null -w "%{http_code}" https://mimikri.<tld>/healthz
# Expected: 401 (Access challenge — desired)

# Postgres replica synced
ssh opsec@mimikri-box1 'sudo -u postgres psql -c "SELECT application_name, state, replay_lag FROM pg_stat_replication;"'
# Expected: mimikri-box3 / streaming / lag < 5s

# Ollama responding
curl -fsSL http://mimikri-box2:11434/api/tags | jq '.models | length'
# Expected: >= 1

# DO API auth (requires secrets unlocked per 08 §4.3)
ssh opsec@mimikri-box1 'sudo -u mimikri bash -c ". /run/mimikri/secrets.env && curl -s -H \"Authorization: Bearer \$DO_TOKEN\" https://api.digitalocean.com/v2/account | jq .account.email"'
# Expected: your DO email
```

If any check fails → fix before proceeding.

---

## 2. Configure scope

`/opt/mimikri/etc/policy.json` — add the smoke scope:

```jsonc
{
  "programs": {
    "smoke-test-2026": {
      "in_scope":     ["scanme.nmap.org", "45.33.32.156"],
      "out_of_scope": []
    }
  }
}
```

Sync:
```bash
sudo install -o mimikri -g mimikri -m 0640 policy.json /opt/mimikri/etc/policy.json
sudo systemctl reload redteam-coordinator || sudo systemctl restart redteam-coordinator
```

---

## 3. Launch test campaign

```bash
ssh opsec@mimikri-box1

# Enqueue target into scan_queue
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam <<EOF
INSERT INTO scan_queue (host, target_type, tactical_context, priority)
VALUES (
  'scanme.nmap.org',
  'Web',
  '{"scope_id": "smoke-test-2026", "allow_destructive_probes": false}'::jsonb,
  100
);
EOF
```

Coordinator is already running and watching the queue. Within a few seconds it should spawn a DO droplet.

---

## 4. Monitor in real time

### 4.1 Coordinator log (Box1)
```bash
ssh opsec@mimikri-box1 'sudo journalctl -fu redteam-coordinator'
```

Expected sequence:
```
INFO  redteam_rust_core::core::engine: Coordinator started
INFO  redteam_rust_core::infrastructure::digital_ocean: Spawning droplet mimikri-worker-<uuid>
INFO  redteam_rust_core::infrastructure::digital_ocean: Droplet <uuid> running, waiting for tailnet
INFO  redteam_rust_core::infrastructure::digital_ocean: Droplet <uuid> joined tailnet at 100.x.y.z
INFO  redteam_rust_core::orchestrator: Worker do-<uuid> claimed job for scanme.nmap.org
```

### 4.2 Worker existence (DO)
```bash
doctl compute droplet list --tag-name campaign:smoke-test-2026
```

### 4.3 Tailnet membership
```bash
tailscale status | grep worker
```

### 4.4 Findings stream (Box1 Postgres)
```bash
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam \
  -c "SELECT category, severity, title, host, created_at FROM findings WHERE scope_id='smoke-test-2026' ORDER BY created_at DESC LIMIT 20;"
```

### 4.5 Dashboard (browser)
Navigate to `https://mimikri.<tld>/?token=<token>` → ROI tab + Findings tab show smoke-test-2026 activity.

### 4.6 Loki / Grafana (browser)
Open `http://mimikri-box3:3000` (Tailscale) → Mimikri folder → `01-scan-throughput.json` dashboard.

---

## 5. Validate scope enforcement

Inject an OUT-OF-SCOPE host into the queue to verify the dual-gate works:

```bash
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam <<EOF
INSERT INTO scan_queue (host, target_type, tactical_context, priority)
VALUES (
  'example.com',
  'Web',
  '{"scope_id": "smoke-test-2026", "allow_destructive_probes": false}'::jsonb,
  100
);
EOF

# Wait 30s, then check
sleep 30
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam \
  -c "SELECT host, category, severity, title FROM findings WHERE host='example.com';"
```

**Expected**: one finding with category `Misconfiguration` and title `Target 'example.com' is out of authorized scope!` — the scope_guard fired correctly. **NO** subsequent findings for example.com.

If actual scan findings appear: scope enforcement is broken — file SEV-0 incident.

---

## 6. Validate destructive gate

Try to force a destructive plugin without the env var:

```bash
# Should be blocked: REDTEAM_DESTRUCTIVE not set
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam <<EOF
INSERT INTO scan_queue (host, target_type, tactical_context, priority)
VALUES (
  'scanme.nmap.org',
  'Web',
  '{"scope_id": "smoke-test-2026", "allow_destructive_probes": true, "force_destructive_plugin": "test_destructive"}'::jsonb,
  100
);
EOF

# Check coordinator log
ssh opsec@mimikri-box1 'sudo journalctl -u redteam-coordinator | grep -i "destructive plugin.*blocked" | tail -5'
```

**Expected**: log line `Destructive plugin <name> blocked: REDTEAM_DESTRUCTIVE not set`.

---

## 7. Validate kill-switch

While the smoke scan is still running:

```bash
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator'

# Check droplets within 30s
sleep 30
doctl compute droplet list --tag-name campaign:smoke-test-2026
# Expected: empty
```

If droplets remain after 60s → kill-switch broken, file SEV-1.

Restart coordinator for further validation:
```bash
ssh opsec@mimikri-box1 'sudo systemctl start redteam-coordinator'
```

---

## 8. Validate AI enrichment

Pick one finding from the smoke run, look up its enrichment:

```bash
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam <<EOF
SELECT id, title, enrichment
FROM findings
WHERE scope_id='smoke-test-2026'
  AND enrichment IS NOT NULL
LIMIT 1;
EOF
```

**Expected**: `enrichment` field contains a JSON blob with at least an `ai_summary` populated by Ollama. If empty → Box2 enrichment worker not running.

---

## 9. Validate observability path

### 9.1 Auditd alert
Trigger a benign auditd event on Box1:
```bash
ssh opsec@mimikri-box1 'sudo touch /etc/sudoers.d/test-trigger && sudo rm /etc/sudoers.d/test-trigger'
```

Within 60s, the event should appear in Loki:
```bash
curl -G http://mimikri-box3:3100/loki/api/v1/query_range \
  --data-urlencode 'query={job="auditd",host="mimikri-box1"} |~ "sudoers"' \
  --data-urlencode "start=$(date -u -d '5 min ago' +%s)000000000" \
  | jq '.data.result[].values | length'
# Expected: >= 1
```

### 9.2 Cloudflare Access log
Open the dashboard via browser (re-trigger Cloudflare Access). Within 5 min:
```bash
ssh opsec@mimikri-box1 'sudo journalctl -t cf-access --since "-5 min" | tail -5'
# Expected: JSON log line with your login
```

---

## 10. Validate ROI baseline collection

Phase 0 telemetry should populate `mcp_stats`:

```bash
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam \
  -c "SELECT program, findings_per_hour, success_rate, last_updated FROM mcp_stats WHERE program='smoke-test-2026';"
```

**Expected**: row exists with non-zero `findings_per_hour`. If empty → `boot/telemetry.rs` Phase 0 baseline not running.

ROI score should be computable:
```bash
curl -fsSL http://mimikri-box1:8080/api/roi/ranking \
  -H "X-Dashboard-Token: $(ssh opsec@mimikri-box1 'sudo -u mimikri cat /opt/mimikri/workspace/logs/dashboard.token')" \
  | jq '.[] | select(.program=="smoke-test-2026")'
```

---

## 11. Cleanup

```bash
# Stop scan
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator'

# Clear smoke findings
sudo -u mimikri psql -h mimikri-box1 -U mimikri redteam <<EOF
DELETE FROM findings WHERE scope_id = 'smoke-test-2026';
DELETE FROM scan_queue WHERE host IN ('scanme.nmap.org', 'example.com');
DELETE FROM mcp_stats WHERE program = 'smoke-test-2026';
EOF

# Remove smoke scope from policy.json
# (manual edit, remove "smoke-test-2026" entry)
sudo systemctl restart redteam-coordinator

# Snapshot all 3 boxes (clean post-smoke state)
for b in box1 box2 box3; do
  oci compute boot-volume-backup create \
    --boot-volume-id <ocid-$b> \
    --display-name "post-smoke-$(date +%F)"
done
```

---

## 12. Sign-off checklist

Print and complete:

```
Smoke test executed: 2026-__-__ by ______________

[ ] Pre-flight all green
[ ] Coordinator spawned ≥1 droplet within 90s of queue insert
[ ] Worker joined tailnet
[ ] At least 5 findings produced for scanme.nmap.org
[ ] Out-of-scope target blocked with SCOPE_VIOLATION finding
[ ] Destructive plugin blocked (env var missing)
[ ] Kill-switch destroyed all droplets within 30s
[ ] AI enrichment populated for at least 1 finding
[ ] Auditd event reached Loki within 60s
[ ] Cloudflare Access logs ingested
[ ] ROI mcp_stats row created for smoke-test-2026
[ ] Cleanup complete
[ ] Post-smoke snapshots taken

Operator signature: ______________________
```

Save signed-off copy in `workspace/drills/smoke-$(date +%F).md`.

---

## 13. What "ready for production" means

After a passing smoke test, the deployment is ready for **authorized bug bounty work under operator supervision**.

It is **not yet** ready for:
- Unattended overnight scans (no auto-resume of Coordinator)
- Multi-operator access (current ACL is single-operator)
- Compliance-bound engagements (no signed audit logs yet)
- Production SLA commitments

Track those graduation gates in `00_OVERVIEW.md` §6 (cadence) and Sprint 10+ work items.

---

## 14. If a check fails

| Failing check | Likely culprit | Refer to |
|---|---|---|
| Coordinator doesn't spawn | DO_TOKEN missing, NATS unreachable | `08`, `02 §3` |
| Worker doesn't join tailnet | Auth-key expired, ACL wrong | `05 §3`, `05 §6` |
| Findings empty | Worker can't reach Postgres | `02 §2.6`, `05 §3` |
| Out-of-scope not blocked | scope_guard.rs not in path | C3 fix in Sprint 9 |
| Destructive plugin runs | Dual-gate broken | C4 fix in Sprint 9 |
| Kill-switch leaves droplets | DO API rate limit | `09 §7` |
| Enrichment empty | Box2 down, Ollama OOM | `03 §9` |
| No Loki ingestion | Promtail not on box | `04 §6.6` |
| Cloudflare Access logs missing | API token wrong | `07 §7` |

Re-run smoke test after each fix. Do not promote to "ready" with any check failing.
