# 🌐 Plan de Despliegue: Arquitectura Distribuida Multi-VPS

Este documento detalla la estrategia para integrar un segundo VPS de Oracle (ARM 24GB) al ecosistema OsintUltimate, optimizando el uso de RAM y garantizando la seguridad operativa (OpSec).

## 0. Arquitectura Objetivo

- **VPS 1 (Maestro):** Orquestación, Base de Datos PostgreSQL, MCP Server y Persistencia.
- **VPS 2 (Cómputo/IA):** Inferencia de IA (Ollama), Worker de escaneo y Proxy de salida estático.
- **Red:** Todo el tráfico inter-nodo ocurre exclusivamente vía **Tailscale**.

---

## 🛠️ Fase 1: Migración de IA (Ollama Offload)
**Objetivo:** Liberar ~12GB de RAM en el VPS 1 para aumentar la concurrencia de escaneo.

### Pasos en VPS 2 (Secundario):
1. **Instalar Ollama:**
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
2. **Configurar para Red Privada:**
   Editar `/etc/systemd/system/ollama.service` y añadir la variable de entorno para que escuche **solo** en la IP de Tailscale (Cero exposición pública):
   ```ini
   [Service]
   Environment="OLLAMA_HOST=<IP_TAILSCALE_DEL_VPS2>:11434"
   ```
3. **Refrescar y Descargar Modelos (Qwen 2.5):**
   ```bash
   systemctl daemon-reload
   systemctl restart ollama
   ollama pull qwen2.5:14b  # Modelo Premium
   ollama pull qwen2.5:3b   # Modelo Lite
   ```

### Pasos en VPS 1 (Principal):
1. **Actualizar `.env`:**
   ```bash
   OLLAMA_URL=http://<IP_TAILSCALE_DEL_VPS2>:11434
   ```
2. **Reiniciar servicio:** `systemctl restart osint-ultimate`

---

## 🛡️ Fase 2: Proxy de Egreso Permanente (OpSec)
**Objetivo:** Usar la IP del VPS 2 como salida secundaria para recon pasivo y reducir costes de DigitalOcean.

### Pasos en VPS 2:
1. **Instalar Dante (SOCKS5):**
   ```bash
   sudo apt update && sudo apt install dante-server
   ```
2. **Configuración (`/etc/danted.conf`):**
   ```conf
   logoutput: stderr
   internal: <IP_TAILSCALE_DEL_VPS2> port = 1080
   external: <INTERFAZ_PUBLICA_ETH0>
   clientmethod: none
   socksmethod: none
   user.privileged: root
   user.unprivileged: nobody

   client pass {
       from: 100.64.0.0/10 to: 0.0.0.0/0
       log: connect error
   }

   socks pass {
       from: 100.64.0.0/10 to: 0.0.0.0/0
       log: connect error
   }
   ```
   *Nota: Sustituir `100.64.0.0/10` por el rango real de Tailscale.*

---

## 🚀 Fase 3: Modo Worker (Escalabilidad)
**Objetivo:** Repartir el trabajo de escaneo activo entre ambos servidores.

### Requisitos Técnicos:
1. **Acceso a DB:** Configurar PostgreSQL en VPS 1 para aceptar conexiones desde la IP de Tailscale del VPS 2 (`pg_hba.conf`).
2. **Cola de Tareas:** Implementar el modo `--worker` en el binario de Rust que consuma objetivos desde una tabla `scan_queue` en PostgreSQL.
3. **Flujo de Trabajo:**
   - VPS 1 inserta objetivos descubiertos en la cola.
   - VPS 2 (Worker) reclama N objetivos, los escanea y escribe los hallazgos directamente en la DB del VPS 1.

---

## 🔒 Seguridad y Firewall (UFW)

Para evitar que servicios críticos queden expuestos a Internet, aplicar estas reglas en **ambos** VPS:

```bash
# Permitir todo el tráfico interno de Tailscale
sudo ufw allow in on tailscale0
# Bloquear acceso público a Ollama y Dante
sudo ufw deny 11434
sudo ufw deny 1080
# Bloquear acceso público a PostgreSQL
sudo ufw deny 5432
```

---

## 🔱 Fase 4: Descentralización via NATS (Mesh Operativo)
**Objetivo:** Sincronización en tiempo real de hallazgos y Kill-Switch distribuido.

### Configuración del Bus NATS:
1. **Desplegar Servidor NATS:** En el VPS 1 (Maestro).
2. **Conexión de Nodos:**
   ```bash
   # En VPS 2 (Worker)
   ./mimikri --nats-url nats://<IP_TAILSCALE_VPS1>:4222 --node-id node-2 --target targets.txt
   ```

### Capacidades Distribuidas:
- **NatsSink:** Los hallazgos se publican instantáneamente en el canal `mimikri.findings.<host>`, permitiendo que cualquier nodo suscrito vea los resultados sin esperar a que termine el escaneo.
- **Global Kill-Switch:** Si se detecta compromiso en cualquier nodo, la señal de bloqueo de egreso se propaga por NATS, cerrando las comunicaciones de salida en TODA la malla de forma coordinada.

---

## 📊 Beneficios Esperados
- **RAM Disponible en VPS 1:** Incremento de ~50%.
- **Concurrencia:** Aumento de 10 a 25 hilos de escaneo simultáneos.
- **Coste:** Reducción de dependencia en droplets efímeros de DigitalOcean para tareas de bajo ruido.
- **Velocidad:** Inferencia de IA más estable al tener recursos dedicados.
