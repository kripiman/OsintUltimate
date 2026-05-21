# 08 — Secrets Management (age + YubiKey + tmpfs)

Stores all sensitive credentials encrypted at rest with a hardware-backed identity on the operator's YubiKey. **Zero $ cost. No cloud secret manager. No third party holds the decryption key.**

Design choice rationale (operator-confirmed):
- The deployment must run indefinitely on Oracle always-free tier, even after the $300 promotional credit expires.
- The system must never auto-bill if the operator runs out of bank funds.
- Therefore: no paid secret manager (OCI Vault was the original design; removed).

---

## 1. Secrets inventory

| Secret | Sensitivity | Used by | Rotation |
|---|---|---|---|
| `DATABASE_URL` (Postgres pass) | High | All boxes + workers | 90d |
| `DO_TOKEN` | Critical | **Box2** (spawn/destroy droplets) | 90d |
| `TAILSCALE_AUTH_KEY` (worker) | High | DO worker bootstrap | 90d |
| `H1_API_KEY` (HackerOne) | High | Box1 (bug bounty submit) | 90d |
| `INTERACTSH_TOKEN` | Critical | Box4 server + Box2 poll + DO workers | 90d |
| `INTERACTSH_URL` | Medium | Box2 (polling) + DO workers (payload gen) | static |
| `SHODAN_STUDENT_API_KEY` | Medium | Workers | 365d |
| `SHODAN_API_KEY` (paid) | High | Workers | 365d |
| `NETLAS_API_KEY` | Medium | Workers | 365d |
| `CHAOS_API_KEY` | Medium | Workers | 365d |
| `SECURITYTRAILS_API_KEY` | Medium | Workers | 365d |
| `CRIMINALIP_API_KEY` | Medium | Workers | 365d |
| `FOFA_KEY` | Medium | Workers | 365d |
| `ZOOMEYE_KEY` | Medium | Workers | 365d |
| `GREYNOISE_API_KEY` | Medium | Workers | 365d |
| `NVD_API_KEY` | Low | Box3 (CVE poll) | 365d |
| `CAIDO_API_KEY` | Medium | Workers (HTTP intercept) | 365d |
| `CF_API_TOKEN` (Cloudflare) | High | Box1 (Access log pull) | 90d |
| `CLOUDFLARE_TUNNEL_TOKEN` | High | Box1 (dashboard tunnel) | 90d |
| `OTEL_BASIC_AUTH` | Low | Boxes (telemetry push) | 365d |
| `DASHBOARD_TOKEN` | High | Operator + Cloudflare Access | per-session |
| `AGE_RECIPIENT_KEY` | Critical | Operator (master encrypt) | never (YubiKey-bound) |

All secrets bundle into a single `secrets.env` file, encrypted into `secrets.env.age`.

---

## 2. Master identity — `age-plugin-yubikey`

Tool: https://github.com/str4d/age-plugin-yubikey

### 2.1 Generate identity on YubiKey

Operator workstation, YubiKey 5 inserted:

```bash
# Install plugin
cargo install age-plugin-yubikey      # or brew install / apt depending on platform

# Generate hardware-bound identity
age-plugin-yubikey --generate \
  --name mimikri-master \
  --pin-policy once \
  --touch-policy always

# Output:
#   Recipient: age1yubikey1qx... (PUBLIC — safe to commit)
#   Identity:  AGE-PLUGIN-YUBIKEY-... (PRIVATE handle; secret material stays on YubiKey)
```

### 2.2 Store the recipient

`infrastructure/recipients.txt` in the repo (committed):
```
# Mimikri operator master recipient — encrypts to YubiKey
age1yubikey1qx...
```

The recipient is not secret. The corresponding private key never leaves the YubiKey hardware.

### 2.3 Save identity handle

`~/.config/age/identities.txt` on operator workstation (NOT committed):
```
AGE-PLUGIN-YUBIKEY-...
```

This handle just tells `age` "use the YubiKey for this identity". The actual key material is on the device.

> [!IMPORTANT]
> Buy a backup YubiKey. Generate a second identity on it with the same `--name`. Add both recipient lines to `recipients.txt`. Loss of the only YubiKey = permanent loss of all secrets.

---

## 3. Encrypt the secrets bundle

### 3.1 Compose `secrets.env` (operator workstation, never committed in plaintext)

```env
# === Critical ===
DATABASE_URL=postgres://mimikri:STRONGPASS@mimikri-box2:5432/redteam
DO_TOKEN=dop_v1_...
TAILSCALE_AUTH_KEY=tskey-auth-...
H1_API_KEY=...
CLOUDFLARE_TUNNEL_TOKEN=...
CF_API_TOKEN=...

# === Box4 Interactsh OOB ===
INTERACTSH_TOKEN=<openssl rand -hex 32 output>
INTERACTSH_URL=https://oast.<your-domain>
INTERACTSH_PUBLIC_IP=<azure-africa-public-ip>
INTERACTSH_DOMAIN=<your-domain>

# === API keys ===
SHODAN_STUDENT_API_KEY=...
SHODAN_API_KEY=...
NETLAS_API_KEY=...
CHAOS_API_KEY=...
SECURITYTRAILS_API_KEY=...
CRIMINALIP_API_KEY=...
FOFA_KEY=...
ZOOMEYE_KEY=...
GREYNOISE_API_KEY=...
NVD_API_KEY=...
CAIDO_API_KEY=...

# === Observability ===
OTEL_BASIC_AUTH=mimikri:<random>
```

### 3.2 Encrypt + shred

```bash
age -R infrastructure/recipients.txt -o secrets.env.age secrets.env
shred -u secrets.env

# Commit ciphertext to private repo (recipients.txt is safe to commit too)
git add secrets.env.age infrastructure/recipients.txt
git commit -S -m "secrets: rotate $(date -u +%Y-%m-%d)"
git push private main
```

The encrypted file is safe to commit — only the YubiKey can decrypt it.

---

## 4. Box-side unlock flow

### 4.1 Sync the ciphertext

Each box has the encrypted bundle at `/opt/mimikri/etc/secrets.env.age`. Initial sync:

```bash
ssh opsec@mimikri-box1
sudo install -d -o root -g mimikri -m 0750 /opt/mimikri/etc
sudo install -o root -g mimikri -m 0640 /path/to/secrets.env.age /opt/mimikri/etc/secrets.env.age
```

Subsequent rotations: operator pulls latest from private git repo (via Tailscale).

### 4.2 Unlock script — `/opt/mimikri/bin/unlock-secrets.sh`

```bash
#!/usr/bin/env bash
# unlock-secrets.sh — decrypt secrets.env.age into /run/mimikri/secrets.env (tmpfs)
# Requires YubiKey inserted on the box during decryption.
# Run as root once per boot.

set -euo pipefail

CIPHERTEXT="/opt/mimikri/etc/secrets.env.age"
RUNDIR="/run/mimikri"
PLAINTEXT="${RUNDIR}/secrets.env"
SERVICE_USER="${1:-mimikri}"        # mimikri / mimikri-ai / mimikri-intel

if [[ ! -f "$CIPHERTEXT" ]]; then
  echo "FATAL: $CIPHERTEXT missing — sync from private repo first" >&2
  exit 1
fi

# Ensure tmpfs directory exists with strict perms
install -d -o root -g "$SERVICE_USER" -m 0750 "$RUNDIR"

# Decrypt — age-plugin-yubikey will prompt for touch
age --decrypt \
  --identity /root/.config/age/identities.txt \
  --output "$PLAINTEXT" \
  "$CIPHERTEXT"

chown root:"$SERVICE_USER" "$PLAINTEXT"
chmod 0640 "$PLAINTEXT"

# Sanity check — DATABASE_URL must be present
if ! grep -q '^DATABASE_URL=' "$PLAINTEXT"; then
  echo "FATAL: decrypted file missing DATABASE_URL" >&2
  shred -u "$PLAINTEXT"
  exit 1
fi

echo "OK: secrets unlocked for $SERVICE_USER. Restart services with:"
echo "  sudo systemctl restart redteam-*"
```

```bash
sudo install -o root -g root -m 0700 unlock-secrets.sh /opt/mimikri/bin/
```

### 4.3 Per-box YubiKey identity

Each box needs `/root/.config/age/identities.txt` referencing the YubiKey handle. Two options:

**Option A (recommended) — Operator inserts YubiKey on the box directly.**

Oracle ARM VMs do not have a USB port. So Option A is impossible for cloud boxes. → use Option B.

**Option B — SSH agent forwarding of the age-plugin-yubikey identity.**

On operator workstation `~/.ssh/config`:
```sshconfig
Host mimikri-box1 mimikri-box2 mimikri-box3
  ForwardAgent yes
  ControlMaster auto
  ControlPath ~/.ssh/cm/%r@%h:%p
  ControlPersist 8h
```

Operator runs unlock from their workstation, decryption happens locally (workstation has the YubiKey), result is piped via SSH to box tmpfs:

```bash
# From operator workstation
age --decrypt \
  --identity ~/.config/age/identities.txt \
  secrets.env.age \
  | ssh opsec@mimikri-box1 'sudo install -m 0640 -o root -g mimikri /dev/stdin /run/mimikri/secrets.env && sudo systemctl restart redteam-coordinator'
```

> [!IMPORTANT]
> The plaintext never touches the box's disk — only the box's tmpfs at `/run/mimikri/secrets.env`. SSH carries the bytes encrypted; tmpfs holds them in RAM only.

Wrapper script `unlock-remote.sh` on operator workstation:
```bash
#!/usr/bin/env bash
set -euo pipefail
BOX="${1:?usage: unlock-remote.sh <boxN> <service-user>}"
SVC_USER="${2:-mimikri}"

age --decrypt -i ~/.config/age/identities.txt secrets.env.age \
  | ssh opsec@"$BOX" "sudo install -d -m 0750 -o root -g $SVC_USER /run/mimikri && sudo install -m 0640 -o root -g $SVC_USER /dev/stdin /run/mimikri/secrets.env && sudo systemctl restart 'redteam-*'"

echo "OK: $BOX unlocked"
```

---

## 5. systemd integration

Each service uses `EnvironmentFile=-/run/mimikri/secrets.env` and `ConditionPathExists=/run/mimikri/secrets.env`:

```ini
[Unit]
Description=Mimikri Coordinator
ConditionPathExists=/run/mimikri/secrets.env
After=network-online.target postgresql.service nats.service tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=mimikri
Group=mimikri
EnvironmentFile=-/run/mimikri/secrets.env
EnvironmentFile=-/opt/mimikri/etc/runtime.env
ExecStart=/usr/local/bin/redteam_rust_core --postgres-url ${DATABASE_URL} --dashboard 8080 --scope-id ${SCOPE_ID}
Restart=on-failure
RestartSec=10
# ... sandboxing as in 02_BOX1 §5.2
```

Behavior:
- Before unlock: `ConditionPathExists` fails → unit inactive → no crash loop
- After `unlock-remote.sh`: file appears → systemctl restart picks up env

---

## 6. Rotation procedure (quarterly)

Run on operator workstation.

```bash
#!/usr/bin/env bash
# rotate-secrets.sh — quarterly secret rotation

set -euo pipefail

# 1. Decrypt current secrets into memory
PLAINTEXT=$(age --decrypt -i ~/.config/age/identities.txt secrets.env.age)

# 2. Generate new values
NEW_PG_PASS=$(openssl rand -base64 32 | tr -d '=+/' | head -c 32)
read -srp "New DO_TOKEN (from DO console): "       NEW_DO_TOKEN ;       echo
read -srp "New Tailscale worker key (from console): " NEW_TS_KEY ;     echo
read -srp "New H1_API_KEY (from console): "        NEW_H1 ;             echo
read -srp "New CF_API_TOKEN (Cloudflare console): " NEW_CF ;            echo
# (Shodan, Netlas, etc. — rotate only if 365d expired)

# 3. Apply Postgres password change on Box1 (over Tailscale)
PSQL="psql -h mimikri-box1 -U postgres"
$PSQL -c "ALTER ROLE mimikri WITH PASSWORD '$NEW_PG_PASS';"

# 4. Compose new secrets.env in-memory
NEW_SECRETS=$(echo "$PLAINTEXT" | sed \
  -e "s|^DATABASE_URL=.*|DATABASE_URL=postgres://mimikri:$NEW_PG_PASS@mimikri-box2:5432/redteam|" \
  -e "s|^DO_TOKEN=.*|DO_TOKEN=$NEW_DO_TOKEN|" \
  -e "s|^TAILSCALE_AUTH_KEY=.*|TAILSCALE_AUTH_KEY=$NEW_TS_KEY|" \
  -e "s|^H1_API_KEY=.*|H1_API_KEY=$NEW_H1|" \
  -e "s|^CF_API_TOKEN=.*|CF_API_TOKEN=$NEW_CF|")

# 5. Re-encrypt
echo "$NEW_SECRETS" | age -R infrastructure/recipients.txt -o secrets.env.age

# 6. Commit signed
git add secrets.env.age
git commit -S -m "secrets: rotate $(date -u +%Y-Q%q)"
git push private main

# 7. Push to each box + unlock
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  scp secrets.env.age opsec@$b:/tmp/secrets.env.age.new
  ssh opsec@$b 'sudo install -o root -g mimikri -m 0640 /tmp/secrets.env.age.new /opt/mimikri/etc/secrets.env.age && rm /tmp/secrets.env.age.new'
  ./unlock-remote.sh "$b" mimikri
done

# 8. Verify
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  ssh opsec@$b 'sudo journalctl -u "redteam-*" -n 20 | grep -i "error\|fatal" || echo "$b clean"'
done

# 9. Revoke old credentials at each provider's console (manual)
echo "MANUAL: revoke old DO_TOKEN in DigitalOcean console"
echo "MANUAL: revoke old Tailscale worker key in admin console"
echo "MANUAL: revoke old CF_API_TOKEN in Cloudflare console"
echo "MANUAL: revoke old H1 token in HackerOne settings"

# 10. Audit log
logger -t mimikri-rotate "secrets rotated: $(date -u +%FT%TZ)"
```

---

## 7. Logging policy for secrets

- **Never log secret values.** `redteam_rust_core` uses `SCRUBBER` (post Sprint 9 H3) on all sink outputs.
- **Never set `RUST_LOG=trace`** on a service that has env-loaded secrets — full env dump risk.
- **No plaintext secrets on disk.** Only `/run/mimikri/secrets.env` (tmpfs, cleared on reboot). No `.env` files in `/opt`, `/etc`, `/home`.
- **Git audit.** Every secrets rotation produces a signed commit. Reviewing `git log secrets.env.age` shows full rotation history.

---

## 8. Verification

```bash
# Recipients file present on operator workstation + boxes
cat infrastructure/recipients.txt | grep ^age1yubikey1

# Ciphertext on each box
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  ssh opsec@$b 'ls -l /opt/mimikri/etc/secrets.env.age'
done

# No plaintext on disk
for b in mimikri-box1 mimikri-box2 mimikri-box3; do
  ssh opsec@$b 'sudo grep -rE "(API_KEY|TOKEN|PASSWORD)=[a-zA-Z0-9]{20,}" /opt /etc 2>/dev/null | grep -v "\.age\|\.example\|/run/"'
done
# Expected: empty

# tmpfs path exists after unlock
ssh opsec@mimikri-box1 'sudo test -f /run/mimikri/secrets.env && echo "unlocked" || echo "locked"'

# YubiKey touch policy enforced
age --decrypt -i ~/.config/age/identities.txt secrets.env.age > /dev/null
# Expected: YubiKey blinks → operator touches → decryption proceeds

# systemd conditions stop services when locked
ssh opsec@mimikri-box1 'sudo systemctl stop redteam-coordinator && sudo rm /run/mimikri/secrets.env && sudo systemctl start redteam-coordinator; sudo systemctl is-active redteam-coordinator'
# Expected: inactive (ConditionPathExists fails); no crash loop in journal
```

---

## 9. Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| YubiKey lost / damaged | All secrets unrecoverable | Buy backup YubiKey at provisioning time; encrypt to BOTH recipients |
| YubiKey PIN forgotten | Cannot decrypt | Reset PIN via PUK; if PUK also lost, YubiKey factory-reset = identity lost |
| SSH agent forwarding misconfigured | `age --decrypt` over SSH fails | Verify `SSH_AUTH_SOCK` set on remote; `ssh -A` flag on connection |
| Box reboots without operator presence | Services stay in `ConditionPathExists` failed state | This is by design — services come up only when operator unlocks. Acceptable for low-reboot Oracle ARM uptime. |
| `secrets.env` persists past intended scope | Held in `/run/mimikri/secrets.env` indefinitely | Add timer to shred + recreate every 24h, forcing daily re-unlock; or accept that tmpfs clears on reboot anyway |
| Different services need different env subset | All services see all secrets | Acceptable for single-operator deploy; or split into per-service `.age` files keyed to per-service age recipients |
| age-plugin-yubikey not packaged for Linux ARM64 | Cannot install on Oracle box | Build from source via `cargo install age-plugin-yubikey`; or use workstation-side decryption (Option B in §4.3) — Oracle box never runs the plugin |
| Postgres password rotation breaks active workers mid-scan | Worker session drops | Drain queue before rotation, or accept worker restart |
| `git commit -S` fails | No GPG signing key | Configure `git config user.signingkey <key-id>` and `git config commit.gpgsign true` |

---

## 10. Why this design suits the operator threat model

| Concern | Addressed by |
|---|---|
| "If I run out of money, the system must keep working" | Zero $ active spend on secret manager |
| "Don't auto-bill on emergency" | No paid service in the secrets path |
| "Encrypt at rest with hardware" | YubiKey holds the decryption identity |
| "Decryption key must not be on the cloud box" | SSH agent forwarding from operator workstation; key material never on Oracle disk |
| "Audit trail for rotations" | Signed git commits + `mimikri-rotate` logger tag in Loki |
| "Recover if YubiKey lost" | Backup YubiKey with same recipient |

Proceed to `02_BOX1_COORDINATOR.md`.
