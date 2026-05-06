# 🛡️ Runbook de Seguridad: Nodo Trabajador (VPS 2)

Este documento es una versión optimizada y endurecida del Runbook principal, específicamente diseñada para el **Segundo VPS (Worker/AI Node)** de Oracle ARM.

## 0. Filosofía de Seguridad
- **Cero Exposición Pública:** Ningún servicio (IA, Proxy, Scanners) escucha en la IP pública.
- **Acceso Único:** Solo se permite la gestión vía SSH (llave privada) y la comunicación interna vía Tailscale.
- **Mínimos Privilegios:** El servicio de IA y los workers corren bajo usuarios sin privilegios.

---

## 1. Hardening del Sistema Operativo

### 1.1 Actualización y Usuario
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git build-essential ufw fail2ban

# Configurar Fail2ban (Igual que VPS 1)
sudo tee /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
sudo systemctl enable --now fail2ban

# Crear usuario para tareas de escaneo
sudo useradd -m -s /bin/bash osint-worker
sudo usermod -aG docker osint-worker
```

### 1.2 Instalación de Tailscale
```bash
# Instalar binario oficial
curl -fsSL https://tailscale.com/install.sh | sh

# Autenticar y etiquetar como servidor
sudo tailscale up --advertise-tags=tag:server
```
*Nota: Requiere actualizar ACLs en VPS 1 (§9.2 del Runbook principal).*

### 1.3 Firewall UFW (Configuración Estricta)
```bash
# Bloquear todo por defecto
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Permitir SSH (Solo si tienes IP estática, si no, usa Tailscale para SSH)
sudo ufw allow 22/tcp comment "SSH"

# Permitir Tailscale (WireGuard)
sudo ufw allow 41641/udp comment "Tailscale NAT"

# Permitir TODO desde la red interna de Tailscale
sudo ufw allow in on tailscale0

# Bloquear explícitamente puertos sensibles en la IP pública
sudo ufw deny 11434/tcp comment "Ollama Public Block"
sudo ufw deny 1080/tcp comment "Proxy Public Block"

sudo ufw --force enable
```

---

## 2. Configuración Segura de Ollama (Fase 1)

Para evitar que tu IA sea usada por terceros, forzamos el bind a la IP interna de Tailscale.

1. **Obtener tu IP de Tailscale:**
   ```bash
   tailscale ip -4
   ```
2. **Editar el servicio:** `sudo systemctl edit ollama.service`
3. **Añadir el bind específico:**
   ```ini
   [Service]
   Environment="OLLAMA_HOST=<TU_IP_TAILSCALE>:11434"
   ```
4. **Reiniciar:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart ollama
   ```

---

## 3. Hardening de Red (Sysctl)
Copia esto en `/etc/sysctl.d/99-worker-hardened.conf` para mitigar ataques de red:

```conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.randomize_va_space = 2
```
Aplicar con: `sudo sysctl -p /etc/sysctl.d/99-worker-hardened.conf`

---

## 4. Configuración Segura de Proxy (Fase 2)
Si instalas Dante (SOCKS5), asegúrate de que el archivo `danted.conf` tenga estas líneas de control:

```conf
internal: <TU_IP_TAILSCALE> port = 1080
external: eth0
clientmethod: none
socksmethod: none

# Solo permitir conexiones desde el rango de Tailscale
client pass {
    from: 100.64.0.0/10 to: 0.0.0.0/0
}
socks pass {
    from: 100.64.0.0/10 to: 0.0.0.0/0
}
```

---

## 5. Monitoreo de Seguridad
Para ver si alguien está intentando entrar:
- **Intentos SSH:** `sudo tail -f /var/log/auth.log`
- **Logs de Ollama:** `journalctl -u ollama -f`
- **Estado de Red:** `sudo ufw status verbose`

---

> [!IMPORTANT]
> Este nodo **no debe tener Nginx ni bases de datos expuestas**. Si necesitas ver estadísticas, consúltalas siempre desde el Dashboard del **VPS 1** a través de la red Tailscale.
