# 01 — Base OS Hardening (All 3 Oracle Boxes)

Apply this runbook to **every** Oracle box (Box1, Box2, Box3) **before** assigning roles.

Target OS: **Ubuntu 22.04 LTS minimal** on `VM.Standard.A1.Flex` (4 OCPU / 24GB RAM ARM).
Estimated time: 60 min per box.

---

## 1. Pre-flight (operator workstation)

```bash
# Generate per-box SSH keypair, hardware-backed if YubiKey present
ssh-keygen -t ed25519-sk -C "operator@$(hostname)-box1" -f ~/.ssh/mimikri_box1
ssh-keygen -t ed25519-sk -C "operator@$(hostname)-box2" -f ~/.ssh/mimikri_box2
ssh-keygen -t ed25519-sk -C "operator@$(hostname)-box3" -f ~/.ssh/mimikri_box3

# If no YubiKey, fallback to ed25519 with passphrase
# ssh-keygen -t ed25519 -a 256 -C "operator@$(hostname)-box1" -f ~/.ssh/mimikri_box1
```

Add to `~/.ssh/config`:
```sshconfig
Host box1
  HostName <public-ip-box1>
  User opc
  IdentityFile ~/.ssh/mimikri_box1
  IdentitiesOnly yes
  PasswordAuthentication no
  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com

# Repeat for box2, box3
```

Provision VM via Oracle console with this initial key in `cloud-init authorized_keys`. **Do NOT use the default `opc` password.**

---

## 2. First-boot lockdown (run as `opc`, then disable)

```bash
ssh box1

# Update everything immediately
sudo apt update && sudo apt full-upgrade -y
sudo apt autoremove --purge -y

# Hostname (per box)
sudo hostnamectl set-hostname mimikri-box1  # mimikri-box2 / mimikri-box3
echo "127.0.1.1 mimikri-box1" | sudo tee -a /etc/hosts

# Timezone (UTC mandatory — avoids log correlation issues)
sudo timedatectl set-timezone UTC
sudo timedatectl set-ntp true

# Install hardening toolset
sudo apt install -y \
  ufw fail2ban unattended-upgrades \
  auditd aide rkhunter chkrootkit \
  apparmor-utils apparmor-profiles \
  systemd-journal-remote rsyslog \
  curl gnupg jq git age \
  build-essential pkg-config libssl-dev libpq-dev \
  postgresql-client-15
```

---

## 3. Create unprivileged operator user

Never run services as `root` or default `opc`. Each role-specific user is created in role runbooks (Box1: `mimikri`, Box2: `mimikri-ai`, Box3: `mimikri-intel`). Here we create the base **administrative** user.

```bash
sudo useradd -m -s /bin/bash -G sudo,adm,systemd-journal opsec
sudo mkdir -p /home/opsec/.ssh
sudo chmod 700 /home/opsec/.ssh

# Copy your operator SSH pubkey
echo "ssh-ed25519-sk AAAAC3Nz... operator@workstation" | sudo tee /home/opsec/.ssh/authorized_keys
sudo chmod 600 /home/opsec/.ssh/authorized_keys
sudo chown -R opsec:opsec /home/opsec/.ssh

# Force MFA for sudo (TOTP via PAM)
sudo apt install -y libpam-google-authenticator
# Run as opsec ONCE: google-authenticator -t -d -r 3 -R 30 -W
# Add to /etc/pam.d/sudo BEFORE @include common-auth:
echo "auth required pam_google_authenticator.so nullok" | sudo tee -a /etc/pam.d/sudo
```

> [!IMPORTANT]
> After confirming `ssh opsec@box1` works AND `sudo -i` requests TOTP, disable `opc` login: `sudo passwd -l opc && sudo usermod -s /sbin/nologin opc`.

---

## 4. SSH hardening

`/etc/ssh/sshd_config.d/99-hardening.conf`:

```sshd_config
# Identity
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
# (delete /etc/ssh/ssh_host_rsa_key and ssh_host_ecdsa_key)

# Auth
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers opsec
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 20

# Crypto
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

# Hardening
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local       # needed for tailscale local-only
PermitUserEnvironment no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE

# Banner
Banner /etc/issue.net
```

`/etc/issue.net`:
```
==============================================================
 AUTHORIZED USE ONLY. All activity is logged and monitored.
 Unauthorized access is prosecutable under applicable law.
==============================================================
```

```bash
sudo rm -f /etc/ssh/ssh_host_rsa_key* /etc/ssh/ssh_host_ecdsa_key*
sudo sshd -t                              # validate config
sudo systemctl restart ssh
```

**Test from new shell** (do not close current session yet): `ssh opsec@box1`. If success, close old session.

---

## 5. Firewall — UFW default-deny

```bash
sudo ufw default deny incoming
sudo ufw default deny outgoing      # zero-trust: explicit allow only
sudo ufw default deny routed

# Loopback
sudo ufw allow in on lo
sudo ufw allow out on lo

# SSH only from Tailscale subnet (after Tailscale setup, see 05_TAILSCALE_MESH.md)
# TEMPORARY: allow SSH from operator workstation public IP until Tailscale is up
sudo ufw allow from <OPERATOR_HOME_IP>/32 to any port 22 proto tcp comment 'temp ssh from operator'

# Outbound: DNS, NTP, HTTPS for apt + Tailscale + cloud APIs
sudo ufw allow out 53/udp comment 'DNS'
sudo ufw allow out 53/tcp comment 'DNS over TCP'
sudo ufw allow out 123/udp comment 'NTP'
sudo ufw allow out 443/tcp comment 'HTTPS'
sudo ufw allow out 80/tcp comment 'HTTP apt'
sudo ufw allow out 41641/udp comment 'Tailscale'

# Logging
sudo ufw logging medium
sudo ufw --force enable
sudo ufw status verbose
```

> [!WARNING]
> After Tailscale is up (`05_TAILSCALE_MESH.md`), REMOVE the temporary public-IP SSH rule:
> ```bash
> sudo ufw delete allow from <OPERATOR_HOME_IP>/32 to any port 22 proto tcp
> sudo ufw allow in on tailscale0 to any port 22 proto tcp comment 'ssh via tailscale only'
> ```

---

## 6. Kernel hardening (sysctl)

`/etc/sysctl.d/99-mimikri-hardening.conf`:

```ini
# Network — protect against spoofing/SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Kernel — ASLR, ptrace restriction, dmesg
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# Disable IP forwarding (Box1/2/3 are NOT routers)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
```

```bash
sudo sysctl --system
```

---

## 7. Disable unnecessary services

```bash
# List enabled units
systemctl list-unit-files --state=enabled

# Disable typical fluff
sudo systemctl disable --now \
  snapd.service snapd.socket \
  ModemManager.service \
  cups.service cups.socket cups.path \
  bluetooth.service \
  avahi-daemon.service avahi-daemon.socket \
  whoopsie.service apport.service \
  motd-news.service motd-news.timer 2>/dev/null || true

# Mask to prevent re-enable
sudo systemctl mask snapd.service
```

---

## 8. Automatic security updates

`/etc/apt/apt.conf.d/50unattended-upgrades`:

```conf
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
    "linux-image-*";  // delay kernel updates to scheduled maintenance
};
Unattended-Upgrade::DevRelease "never";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "operator@your-email.tld";
Unattended-Upgrade::MailReport "on-change";
```

`/etc/apt/apt.conf.d/20auto-upgrades`:
```conf
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```

```bash
sudo systemctl enable --now unattended-upgrades
sudo unattended-upgrade --dry-run --debug | tail -20
```

---

## 9. fail2ban for SSH + auth

`/etc/fail2ban/jail.d/mimikri.conf`:
```ini
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
backend = systemd
banaction = ufw
destemail = operator@your-email.tld
sender = fail2ban@mimikri
mta = sendmail

[sshd]
enabled = true
mode = aggressive

[sudo]
enabled = true
filter = sudo-auth
logpath = /var/log/auth.log
maxretry = 2
bantime = 48h
```

`/etc/fail2ban/filter.d/sudo-auth.conf`:
```ini
[Definition]
failregex = sudo.*authentication failure.*rhost=<HOST>
            sudo.*: \d+ incorrect password attempts
ignoreregex =
```

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

---

## 10. auditd — full action logging

`/etc/audit/rules.d/99-mimikri.rules`:

```
# Delete all previous rules
-D
-b 8192

# Failures: log to syslog and continue
-f 1

# Identity / auth
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Privileged commands
-a always,exit -F arch=b64 -F euid=0 -S execve -k root_exec
-w /usr/bin/sudo -p x -k sudo_use
-w /var/log/sudo.log -p wa -k sudo_log

# Network config
-w /etc/network/ -p wa -k network
-w /etc/netplan/ -p wa -k network
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network

# Mimikri-specific
-w /opt/mimikri/ -p wa -k mimikri_files
-w /etc/systemd/system/redteam-* -p wa -k mimikri_service
-a always,exit -F arch=b64 -F path=/usr/local/bin/redteam_rust_core -F perm=x -k mimikri_exec

# Module loading
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change

# Make config immutable (prevents tampering even by root without reboot)
-e 2
```

```bash
sudo augenrules --load
sudo systemctl enable --now auditd
sudo auditctl -s
```

---

## 11. AIDE — file integrity baseline

```bash
sudo aideinit -y -f                       # initialize DB (~10 min)
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Daily integrity check via systemd timer
sudo tee /etc/systemd/system/aide-check.service > /dev/null <<'EOF'
[Unit]
Description=AIDE filesystem integrity check
[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
StandardOutput=journal
EOF

sudo tee /etc/systemd/system/aide-check.timer > /dev/null <<'EOF'
[Unit]
Description=Run AIDE check daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now aide-check.timer
```

Re-baseline after each legitimate change (post role-installation):
```bash
sudo aide --update && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

## 12. AppArmor enforcement

```bash
sudo systemctl enable --now apparmor
sudo aa-status

# Set all profiles to enforce mode
for p in /etc/apparmor.d/*; do
  [ -f "$p" ] && sudo aa-enforce "$p" 2>/dev/null || true
done
```

Custom profile for `redteam_rust_core` lives in role-specific runbooks (02/03/04).

---

## 13. Encrypted swap + scratch tmpfs

```bash
# Disable any swap on disk, enable encrypted zram swap (ARM-friendly)
sudo swapoff -a
sudo sed -i '/swap/s/^/#/' /etc/fstab
sudo apt install -y zram-tools
echo -e "ALGO=zstd\nPERCENT=25\nPRIORITY=100" | sudo tee /etc/default/zramswap
sudo systemctl restart zramswap

# /tmp on tmpfs
sudo systemctl enable --now tmp.mount || \
  echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=2G 0 0' | sudo tee -a /etc/fstab

# Remount /home /var /var/log with nodev,nosuid if separate partitions (Oracle default: single root)
# Apply restrictive mount options to /tmp:
sudo mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null || true
```

---

## 14. Log shipping → Box3 (Loki) — placeholder

Configured fully in `04_BOX3_INTEL_OBSERVABILITY.md` once Box3 + Tailscale are up. Stub now:

```bash
sudo apt install -y promtail
# Config dropped in Phase 8
```

## 15. OCI Vulnerability Scanning Service (VSS) (paid tier, credit-funded)

To detect OS vulnerabilities, kernel CVEs, open ports, and CIS benchmark drift on the three control-plane boxes (Box1, Box2, Box3), configure the OCI Vulnerability Scanning Service (VSS).

Allocated from the $300 credit per `HYBRID §7` ($40/yr ≈ continuous scanning for 1 year).

1. **OCI Console Configuration**:
   - Navigate to **Identity & Security** → **Scanning**.
   - Under **Host Scan Recipes**, click **Create Recipe**. Configure it to scan weekly for vulnerabilities and CIS benchmark compliance.
   - Under **Host Scan Targets**, click **Create Target**. Select the compartment containing Box1, Box2, and Box3, and assign the scan recipe.

2. **Verification on Host**:
   VSS relies on the Oracle Cloud Agent running on each Compute Instance. Verify that the scanning plugin is enabled and running:
   ```bash
   # Check if Oracle Cloud Agent is active
   sudo systemctl status oracle-cloud-agent

   # Verify the Vulnerability Scanning plugin is enabled and log activity:
   tail -n 20 /var/log/oracle-cloud-agent/plugins/vulnerability-scanning/agent.log
   ```

Day-350 graduation step (covered in `09 §10`): Export all scanning history and reports, then disable/delete the host scan target in the OCI Console to halt active scanning before paid credits expire.

---

## 16. Verification checklist

```bash
# SSH only via key, no root
sudo grep -E 'PermitRootLogin|PasswordAuthentication|PubkeyAuthentication' /etc/ssh/sshd_config.d/99-hardening.conf

# UFW active, default deny
sudo ufw status verbose | head -5

# auditd loaded immutably
sudo auditctl -s | grep enabled
# Expected: enabled 2

# AppArmor enforcing
sudo aa-status | grep "profiles are in enforce mode"

# fail2ban running
sudo fail2ban-client ping

# No swap on disk
swapon --show
# Expected: /dev/zram0 only

# Unattended-upgrades active
systemctl is-enabled unattended-upgrades

# AIDE timer
systemctl is-enabled aide-check.timer

# Kernel hardening applied
sysctl kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.tcp_syncookies
# Expected: 2, 1, 1

# Oracle Cloud Agent running (for VSS scanning)
systemctl is-active oracle-cloud-agent
```

Sign off with operator initials + date in `/etc/motd`:
```bash
echo "Box hardened per 01_BASE_HARDENING.md on $(date -u +%F) by <YOUR_INITIALS>" | sudo tee -a /etc/motd
```

Take an Oracle snapshot now: this is your "clean baseline" rollback target.

---

## 17. Common pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Lock yourself out before keys load | SSH refused | Keep a second terminal open during step 4 |
| UFW blocks outbound apt | `apt update` hangs | Step 5 — confirm `ufw allow out 80/tcp` and `443/tcp` |
| auditd immutable (-e 2) blocks edits | Cannot reload rules | Reboot required to load new rules |
| TOTP misalignment | `sudo` rejects code | `sudo timedatectl set-ntp true` and confirm `timedatectl status` shows synchronized |
| AppArmor blocks legit binary | Service fails to start | `sudo aa-complain /etc/apparmor.d/<profile>` temporarily, inspect `journalctl -u apparmor` |

Proceed to `05_TAILSCALE_MESH.md` once all 3 boxes pass §16 verification.
