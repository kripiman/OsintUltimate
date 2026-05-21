# 09 — Incident Response Playbooks

Operational runbook for security incidents, outages, and emergency procedures. **Print a hard copy and keep it accessible offline.**

---

## 1. Incident severity matrix

| Severity | Examples | Response time | Notify |
|---|---|---|---|
| **SEV-0 — Catastrophic** | Operator credential breach, target out-of-scope scanned, BB report submitted in error | < 15 min | Operator + affected program |
| **SEV-1 — Critical** | Box1 compromised, kill-switch failure, > $50 surprise bill | < 1 hour | Operator |
| **SEV-2 — High** | Scan results corrupted, droplet orphaned > 24h, Postgres replication broken | < 4 hours | Operator |
| **SEV-3 — Medium** | One box down (other 2 healthy), CertStream lag, model integrity alert | < 24 hours | Operator |
| **SEV-4 — Low** | Disk usage > 80%, certificate expiring < 30d | < 7 days | Operator |

---

## 2. Universal first response (every incident)

1. **Stop the bleeding** — execute kill-switch if active scans are in question (§3).
2. **Preserve evidence** — snapshot Box1 + Box3, freeze logs.
3. **Document timeline** — start a SEV log file: `workspace/incidents/$(date +%F)-<short-desc>.md`. Append timestamped notes.
4. **Communicate** — if target SOC has been visible to scans, prepare an apology/notice as required by program ROE.
5. **Root cause analysis** — postmortem within 72h.

---

## 3. Kill-switch — destroy all DO ephemeral droplets

### Trigger
Operator types Ctrl+C in Box1 dashboard SSH session, OR sends SIGINT to coordinator:

```bash
# Method A — interactive
ssh opsec@mimikri-box1
sudo systemctl stop redteam-coordinator       # graceful → triggers cleanup
# OR
sudo pkill -SIGINT -u mimikri redteam_rust_core

# Method B — emergency from anywhere
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator'
```

### Verification
```bash
# Within 30s
doctl compute droplet list --tag-name purpose:redteam-ephemeral
# Expected: empty

# If NOT empty after 60s — manual destruction:
for id in $(doctl compute droplet list --tag-name purpose:redteam-ephemeral --format ID --no-header); do
  doctl compute droplet delete $id --force
done
```

### What happens internally
1. Coordinator receives SIGINT → `tokio::signal::ctrl_c()` handler
2. `infrastructure::digital_ocean::destroy_all_ephemeral_droplets()` enumerated by tag
3. Parallel DELETE calls to DO API
4. Pending findings in NATS flush to Postgres (best-effort, 30s grace)
5. Coordinator exits clean

### Quarterly drill checklist
- [ ] Spawn 3 test droplets via test-spawn command
- [ ] Verify Tailscale + Postgres connectivity
- [ ] Send SIGINT
- [ ] Within 30s: all droplets destroyed
- [ ] Tailnet shows no `mimikri-worker-*` devices
- [ ] DO billing dashboard shows no new charges within 24h

---

## 4. SEV-0: Operator credential breach

### Detection signals
- Login from unfamiliar country in Cloudflare Access logs
- SSH session from unknown IP in auditd
- Unexpected git push to private repos
- DO/Tailscale console shows resources not created by operator

### Immediate response (within 5 min)
```bash
# 1. Rotate ALL credentials — assume everything in memory is compromised
# Operator workstation:
git -C ~/secrets-repo log -p -10                # check for unauthorized commits

# 2. Revoke compromised SSH key on all 3 boxes (use a secondary device)
ssh -i ~/.ssh/mimikri_box1_BACKUP opsec@mimikri-box1 \
  'echo "" | sudo tee /home/opsec/.ssh/authorized_keys && sudo systemctl restart ssh'
# Repeat for box2, box3

# 3. Trigger kill-switch (§3)
ssh -i ~/.ssh/mimikri_box1_BACKUP opsec@mimikri-box1 \
  'sudo systemctl stop redteam-coordinator'

# 4. Rotate every API key — visit each provider's console
#    DigitalOcean: revoke token → issue new
#    Tailscale: revoke worker auth-key, regenerate
#    HackerOne: revoke API key
#    Cloudflare: rotate API token
#    Shodan, Netlas, Chaos, etc.: revoke + reissue
#    Postgres: change password (over Tailscale from BACKUP key)

# 5. Re-encrypt secrets.env.age + redistribute per 08_SECRETS_MANAGEMENT.md §6

# 6. Restart all services
for b in box1 box2 box3; do
  ssh -i ~/.ssh/mimikri_${b}_BACKUP opsec@mimikri-$b \
    'sudo systemctl restart redteam-*'
done

# 7. Audit: extract last 48h of auditd + journald to forensic archive
ssh -i ~/.ssh/mimikri_box3_BACKUP opsec@mimikri-box3 \
  'sudo journalctl --since "-48h" > /tmp/forensic-$(date +%F).log && \
   sudo ausearch --start -48h > /tmp/forensic-audit-$(date +%F).log && \
   sudo tar czf /tmp/forensic-$(date +%F).tar.gz /tmp/forensic-*.log /var/log/postgresql/'
scp -i ~/.ssh/mimikri_box3_BACKUP opsec@mimikri-box3:/tmp/forensic-$(date +%F).tar.gz ./
```

### Long-term remediation
- Replace YubiKey if physical compromise suspected
- Reissue all SSH keys with fresh entropy
- Rebuild boxes from scratch if root-level compromise confirmed (do not trust the OS)
- Update threat model in `00_OVERVIEW.md` if new attack vector revealed

---

## 5. SEV-0: Out-of-scope target scanned

### Detection
- Finding with `host` matching `out_of_scope` pattern in `policy.json`
- Target SOC contacts operator
- BB program flags account

### Response
```bash
# 1. STOP all current scans immediately
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator'
# Kill-switch destroys all droplets

# 2. Identify scope of the violation
psql -h mimikri-box1 -U mimikri redteam <<EOF
SELECT id, host, scope_id, created_at
FROM findings
WHERE host = '<out-of-scope-host>'
   OR host LIKE '%<oos-pattern>%';
EOF

# 3. Delete affected findings (DO NOT publish or report)
psql -h mimikri-box1 -U mimikri redteam -c \
  "DELETE FROM findings WHERE host LIKE '%<oos-pattern>%' AND submitted = FALSE;"

# 4. Verify no auto-submission happened
psql -h mimikri-box1 -U mimikri redteam -c \
  "SELECT * FROM submitted_reports WHERE host LIKE '%<oos-pattern>%';"
# If any: contact BB program immediately to withdraw

# 5. Root cause: why did the scope guard not block?
# Check policy.json + scope_guard.rs decisions in logs
ssh opsec@mimikri-box3 'sudo journalctl -u redteam-coordinator | grep -i "scope\|<oos-pattern>" | tail -50'
```

### Communication template

```
Subject: [Mimikri] Scope adherence issue — <program>

To: <program-security@example.com>

During automated reconnaissance under the <program> bug bounty program, our scanner briefly probed <host>, which we believe falls outside the program's defined scope (specifically [matching out_of_scope rule]).

Scope of activity:
- Time window: <start> to <stop> UTC
- Probe types: <e.g. DNS lookups, HTTP GET />
- Total requests: <count>
- Source IP(s): <DO droplet IPs>
- No findings were submitted or shared.

Cause: <one-sentence RCA>
Remediation: Scan halted, findings deleted, scope rules updated, post-mortem attached.

Please advise on any additional steps you require.

— Operator
```

---

## 6. SEV-1: Box1 compromised

### Indicators
- AIDE alert on `/usr/local/bin/redteam_rust_core` or systemd units
- auditd `root_exec` rule fires unexpectedly
- New SSH session from non-Tailscale IP
- Unknown processes in `ps`

### Response

```bash
# 1. Isolate — kill Tailscale immediately to cut the attacker off
ssh opsec@mimikri-box1 'sudo systemctl stop tailscaled'
# Box1 is now unreachable; that's the point.

# 2. Take Oracle snapshot for forensics
oci compute boot-volume-backup create --boot-volume-id <id> --display-name "box1-forensic-$(date +%F)"

# 3. Failover to Box3
ssh opsec@mimikri-box3 'sudo -u postgres pg_ctl promote -D /var/lib/postgresql/16/main'
# Update DNS/config so other boxes + workers point to Box3 as primary

# 4. Rebuild Box1 from scratch (do NOT clean and reuse)
oci compute instance terminate --instance-id <box1-ocid> --preserve-boot-volume false
# Provision new VM, walk through 01 → 05 → 08 → 02

# 5. After rebuild, demote Box3 back to replica
```

---

## 7. SEV-1: Kill-switch failure

### Symptom
Ctrl+C / `systemctl stop redteam-coordinator` runs but droplets persist.

### Diagnosis
```bash
# Coordinator log
ssh opsec@mimikri-box1 'sudo journalctl -u redteam-coordinator -n 100 | tail -50'

# DO API error? (Secrets must already be unlocked — see 08 §4.3)
ssh opsec@mimikri-box1 'sudo -u mimikri bash -c ". /run/mimikri/secrets.env && curl -s -H \"Authorization: Bearer \$DO_TOKEN\" https://api.digitalocean.com/v2/account | jq"'
# Check rate limit / 429 / 401
```

### Fallback (manual cleanup)
```bash
# Listing
doctl compute droplet list --tag-name purpose:redteam-ephemeral --format ID,Name,Created

# Parallel destruction
doctl compute droplet list --tag-name purpose:redteam-ephemeral --format ID --no-header \
  | xargs -P 10 -I{} doctl compute droplet delete {} --force

# If doctl also fails — DO web console
# https://cloud.digitalocean.com/droplets → bulk delete
```

### Post-incident
- File bug: kill-switch must reach 100% success even under DO API rate-limit
- Add backoff/retry in `infrastructure/digital_ocean.rs::destroy_all_ephemeral_droplets`
- Add safety net: Box3 janitor cron with shorter interval (5min) during incident response

---

## 8. SEV-1: Surprise bill / cost runaway

### Indicators
- DO billing dashboard shows > $20/month
- Oracle credit burning faster than expected
- Email from provider about usage

### Response
```bash
# 1. Halt all scans
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator'

# 2. Audit current droplets
doctl compute droplet list

# 3. Destroy any unexpected ones
doctl compute droplet list --no-header --format ID | xargs -I{} doctl compute droplet delete {} --force

# 4. Audit Object Storage usage (if Oracle costs)
oci os bucket get --bucket-name mimikri-cold --query 'data."approximate-size"'

# 5. Spending alert tighten
# DO console → Billing → set hard cap to $10
# Oracle: monitor usage in console daily

# 6. Reduce concurrency in coordinator
sed -i 's/MAX_CONCURRENT_DROPLETS=.*/MAX_CONCURRENT_DROPLETS=3/' /opt/mimikri/etc/runtime.env
```

---

## 9. SEV-2: Postgres replication broken

```bash
# Verify on Box1
ssh opsec@mimikri-box1 'sudo -u postgres psql -c "SELECT * FROM pg_stat_replication;"'
# If empty → Box3 not connected

# Verify on Box3
ssh opsec@mimikri-box3 'sudo -u postgres psql -c "SELECT pg_is_in_recovery(), pg_last_wal_replay_lsn();"'

# Common causes
# a) Network: Tailscale down between boxes
ssh opsec@mimikri-box3 'tailscale ping mimikri-box1'

# b) Replication slot exhausted
ssh opsec@mimikri-box1 'sudo -u postgres psql -c "SELECT slot_name, active, restart_lsn FROM pg_replication_slots;"'

# c) Password rotated, conninfo stale
ssh opsec@mimikri-box3 'sudo cat /var/lib/postgresql/16/main/postgresql.auto.conf'

# Resolution: re-base if lag is unrecoverable
ssh opsec@mimikri-box3
sudo systemctl stop postgresql
sudo -u postgres rm -rf /var/lib/postgresql/16/main/*
sudo -u postgres pg_basebackup -h mimikri-box1 -D /var/lib/postgresql/16/main \
  -U replicator -W -P -X stream -R -C -S mimikri_box3_slot
sudo systemctl start postgresql
```

---

## 10. SEV-3: Approaching Oracle credit exhaustion (day 330–360)

Routine maintenance, not an incident in the security sense — but treated as SEV-3 to ensure operator runs the graduation gate before paid services auto-suspend at day 365.

### Trigger signals
- Oracle billing dashboard shows used credit > $250 (≈day 330 at $25/mo burn).
- Email from Oracle: "your promotional credit is about to expire".
- `oci usage-api request-summarized-usages` shows < $50 remaining.

### Graduation gate procedure (~2h)

```bash
# 0. Sanity check current credit + spend
oci usage-api request-summarized-usages \
  --tenant-id <root-ocid> \
  --time-usage-started "$(date -u -d '30 days ago' +%FT%TZ)" \
  --time-usage-ended "$(date -u +%FT%TZ)" \
  --granularity DAILY \
  | jq '.data.items | map(.computed_amount) | add'

# 1. Object Storage — prune oldest archives to fit free tier (≤20GB per tenancy)
for tenancy in box1 box2 box3; do
  oci os bucket get --bucket-name mimikri-cold --tenancy $tenancy --query 'data."approximate-size"' \
    | awk '$0 > 20000000000 { print "PRUNE NEEDED"; exit 1 }'
done
# If prune needed, delete oldest objects:
oci os object list --bucket-name mimikri-cold \
  --query 'data | sort_by(@, &"time-created") | [0:200].name' \
  | xargs -I{} oci os object delete --bucket-name mimikri-cold --object-name {} --force

# 2. Block Volume Backup — export final weekly Postgres snapshot to local NAS
LATEST_BACKUP=$(oci bv backup list --query 'data | sort_by(@, &"time-created") | [-1].id' --raw-output)
oci bv backup export --backup-id "$LATEST_BACKUP" --destination-region <local-or-nas>
# OR: pg_dump the live database into operator's local NAS via WireGuard
ssh opsec@mimikri-box1 'sudo -u postgres pg_dump -Fc redteam' | age -R recipients.txt > ~/nas/final-snapshot-$(date +%F).dump.age

# 3. VSS — export findings before service suspends
oci vss host-cis-benchmark-scan-result-summary list \
  --compartment-id <root-ocid> --all > vss-cis-findings-$(date +%F).json
oci vss host-vulnerability list \
  --compartment-id <root-ocid> --all > vss-vulns-$(date +%F).json

# 4. Logging Analytics — migrate parsing rules to Loki + export raw logs
oci log-analytics parser list --namespace-name <ns> > logan-parsers-$(date +%F).json
# Convert + commit parsers to redteam_rust_core/infrastructure/loki-parsers/ (operator manual step)

# 5. Bastion — confirm session count returns to free-tier cap
oci bastion session list --bastion-id <id> --query 'data | length(@)'

# 6. Verify Always-Free quotas all healthy
for service in compute object-storage block-volume; do
  oci limits resource-availability get --service-name $service --compartment-id <root-ocid>
done

# 7. Confirm no service is in a state that would require billing post-expiry
oci limits limit-value list --service-name compute \
  --query 'data[?"value">`0` && "scope-type"==`AD`]'

# 8. Document graduation in postmortem-style file
cat > workspace/graduations/$(date +%F)-credit-expiry.md <<EOF
# Oracle credit graduation $(date +%F)

Credit balance pre-graduation: \$XX
Object Storage GB used: X.X
Block Volume Backup last export: ...
VSS findings archived: X
Logging Analytics parsers migrated: X

Day 365 auto-suspend executed.
Day 366 status: all services on Always-Free, no billing event.

Operator signature: ___________________
EOF
```

### Day 365 + 1 verification (next morning)

```bash
# Cost dashboard should show $0 usage since expiry
oci usage-api request-summarized-usages \
  --tenant-id <root-ocid> \
  --time-usage-started "$(date -u -d '2 days ago' +%FT%TZ)" \
  --time-usage-ended "$(date -u +%FT%TZ)"
# Expected: zero cost rows

# Always-Free services still active
ssh opsec@mimikri-box1 'systemctl is-active redteam-*'
# Expected: all active

# No "billing event" in account console
# Manually verify: Oracle console → Billing → no invoices issued
```

### What goes wrong + recovery

| Failure | Symptom | Fix |
|---|---|---|
| Object Storage > 20GB at day 365 | Auto-suspend with locked content | Open SR; data accessible read-only, prune to under 20GB to unlock |
| Block Volume Backup not exported in time | Last snapshot inaccessible | Open SR within 30d before Oracle purges; or accept loss (Postgres replica on Box3 + age-encrypted weekly snapshots are independent recovery paths) |
| VSS export missed | Findings history lost | AIDE + auditd logs remain on Box3 Loki |
| Loki parsing rule migration incomplete | New log formats not parsed | Backfill parsers; old logs still searchable |

---

## 11. SEV-3: One box down

If Box2 or Box3 dies but Box1 + workers continue, the system degrades gracefully.

**Box2 down**: AI enrichment paused. Findings accumulate. Restart Box2 → enrichment catches up.

**Box3 down**: Loss of observability + janitor. Workers continue (Box1 covers cleanup). Critical: confirm cloud-init `at +6h shutdown` still runs on every droplet (independent of janitor).

Restoration:
```bash
# Reboot the down box from Oracle console
oci compute instance action --action SOFTRESET --instance-id <ocid>

# Wait for it to come up
oci compute instance get --instance-id <ocid> --query 'data."lifecycle-state"'

# Verify services
ssh opsec@mimikri-box2 'systemctl status redteam-enrichment ollama'
```

---

## 12. Forensic preservation checklist

For any SEV-0 / SEV-1 incident, preserve:

```bash
# On affected box
sudo journalctl --since "-72h" --output=json > /tmp/journal-$(date +%F).json
sudo ausearch --start -72h --raw > /tmp/audit-$(date +%F).log
sudo tar czf /tmp/postgres-logs-$(date +%F).tar.gz /var/log/postgresql/
sudo tar czf /tmp/apparmor-$(date +%F).tar.gz /var/log/audit/audit.log* /var/log/syslog*
sudo cp -r /etc/{ssh,postgresql,nats,cloudflared} /tmp/configs-$(date +%F)/
sudo find /opt/mimikri -newer /tmp/last-clean-state -ls > /tmp/changed-files.txt

# Hash everything
cd /tmp && sha256sum *$(date +%F)* > evidence-$(date +%F).sha256

# Encrypt + ship off-box for chain-of-custody
tar czf evidence-$(date +%F).tar.gz *$(date +%F)*
age -R /opt/mimikri/etc/age-recipient.txt -o evidence-$(date +%F).tar.gz.age evidence-$(date +%F).tar.gz
shred -u evidence-$(date +%F).tar.gz

# Push to OCI Object Storage on Box1 tenancy (within 20GB free allotment, age-encrypted already)
# Authenticate via the `oci` CLI config on the operator workstation; no instance principal required.
oci os object put --bucket-name mimikri-forensics \
  --file evidence-$(date +%F).tar.gz.age
```

---

## 13. Postmortem template

Save as `workspace/incidents/POSTMORTEM-$(date +%F)-<slug>.md`:

```markdown
# Postmortem: <short title>

**Date**: 2026-MM-DD
**Severity**: SEV-X
**Duration**: HH:MM total impact
**Author**: <operator>

## Summary
Two sentences. What happened, what was the impact.

## Timeline (UTC)
- 14:23 — first signal
- 14:25 — operator alerted
- 14:30 — kill-switch fired
- 14:35 — bleeding stopped
- 15:20 — recovery complete

## Root cause
The five-whys analysis.

## Impact
- Targets affected: …
- Data exposed (if any): …
- Financial: $…
- Reputation: …

## Detection — what worked, what didn't
- Alert fired correctly via …
- Did not catch X because …

## Response — what worked, what didn't
- Kill-switch executed cleanly
- Replica failover took 5min vs 2min target

## Action items
| # | Owner | Action | Due |
|---|---|---|---|
| 1 | operator | Add detector for X | 2026-MM-DD |
| 2 | operator | Update threat model in 00 | 2026-MM-DD |
| 3 | operator | Tighten policy.json rule for Y | 2026-MM-DD |

## Lessons learned
What the next operator should remember.
```

Commit postmortems to private repo. Reference in `00_OVERVIEW.md` if threat model needs update.

---

## 14. Drill schedule (quarterly)

| Quarter | Drill | Expected duration |
|---|---|---|
| Q1 | Kill-switch test (3 dummy droplets) | 30 min |
| Q2 | Postgres failover Box1 → Box3 | 1 hour |
| Q3 | Operator credential rotation full cycle | 2 hours |
| Q4 | Box1 destroy + rebuild from scratch | 4 hours |

Document each drill in `workspace/drills/`. Failure of any drill = SEV-2 (system not actually resilient).

---

## 15. After every incident

- [ ] Postmortem written within 72h
- [ ] All action items have owners + dates
- [ ] Threat model in `00_OVERVIEW.md` reviewed
- [ ] Runbook updated if procedure was unclear
- [ ] Recovery key (YubiKey, backup SSH) tested fresh
- [ ] Operator slept

Proceed to `10_SMOKE_TEST.md` to validate the full deployment.
