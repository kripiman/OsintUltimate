# VPS — Alternativas / Clones de DigitalOcean (efímeros o no)

> **Estado**: referencia de operador · **Última revisión**: 2026-09-10
> **Motivo**: DigitalOcean salió del GitHub Student Pack. Este doc lista proveedores que replican el modelo de DO para el **nodo de escaneo (data plane)** del sistema, y distingue cuáles soportan el modelo **efímero** (facturación por hora + API create/destroy) y cuáles no.
> **Fuente de requisitos**: `docs/deployment/06_DO_EPHEMERAL_WORKERS.md`, `docs/deployment/00_OVERVIEW.md`, `docs/deployment/HYBRID_DEPLOYMENT_TOPOLOGY.md`. Precios y AUP **cambian** — verifica en el sitio de cada proveedor antes de comprometer nada.

---

## 1. ¿Qué rol llena este VPS? (importante — no es cualquier nodo)

La arquitectura documentada NO es un solo VPS. Son **4 nodos persistentes + N workers efímeros**:

| Rol | Persistencia | Proveedor documentado | ¿Este doc aplica? |
|---|---|---|---|
| Box1 — AI enrichment | Persistente | Oracle student | No |
| Box2 — Coordinador (Postgres/dashboard/NATS) | **Persistente** | Oracle always-free | No |
| Box3 — Intel/observabilidad | Persistente | Oracle always-free | No |
| Box4 — interactsh OOB | **Persistente** (IP pública estable, DNS) | Azure Student | No |
| **Worker de escaneo (data plane)** | **EFÍMERO por diseño** | **DigitalOcean** ← el hueco | **Sí — este doc** |

Solo el **worker de escaneo** es el rol que DO cubría y que hay que reemplazar. Los demás nodos son persistentes y ya viven en Oracle/Azure. **No pongas el escaneo en Oracle** (el código lo bloquea vía `is_oracle_cloud()` → corta capas Scanning+) **ni en tu PC de casa para escaneos pesados** (ban de IP residencial por WAF, router saturado).

### Requisitos del worker (de `06_DO_EPHEMERAL_WORKERS.md`)
- Tamaño mínimo: **`s-1vcpu-1gb`** (1 vCPU / 1 GB). Los tiers de $5 lo superan de sobra.
- **root / raw sockets** — `nmap -sS`, UDP, OS-detection, masscan necesitan `CAP_NET_RAW`. No atraviesan un proxy SOCKS5, corren desde la IP del nodo.
- **Tolerancia a escaneo saliente** — el proveedor no debe suspenderte por tráfico tipo nmap/nuclei/hydra hacia terceros (aunque el target lo autorice, el proveedor no lo sabe).
- **IP quemable** — modelo efímero: crear → escanear → destruir → IP nueva por campaña, para que el SOC del target no acumule un ban de reputación.
- Modelo de facturación DO: **por hora** (~$0.009/hr para `s-1vcpu-1gb`) + **API/CLI** para create/destroy on-demand.

---

## 2. Clones de DO — ¿efímero o no?

"Efímero" aquí = **facturación por hora (con tope mensual) + API/CLI para crear y destruir instancias on-demand**. Ese es el modelo de DO. Precios aproximados — **verificar**.

| Proveedor | ¿Efímero? | Facturación | API / CLI | Precio aprox (tier ~$5) | Tolerancia a scanning | Regiones |
|---|---|---|---|---|---|---|
| **DigitalOcean** (baseline) | ✅ Sí | Por hora, tope mensual | API + `doctl` | ~$0.009/hr · $6/mo si 24/7 | Media (rota IPs) | Global |
| **Vultr** | ✅ Sí — clon casi exacto de DO | Por hora, tope mensual | API + `vultr-cli` | ~$0.007–0.009/hr | Media (reputación similar a DO) | Global |
| **Linode / Akamai** | ✅ Sí | Por hora, tope mensual | API + `linode-cli` | ~$0.0075/hr · $5/mo | Media | Global |
| **Hetzner Cloud** | ✅ Sí | Por hora, tope mensual | API + `hcloud` | ~€0.007/hr (el más barato) | Media-baja — **actúa rápido ante quejas de abuso** | EU + 2 US |
| **Contabo** | ❌ **No** | **Mensual fija** (a veces fee de setup) | API limitada, aprovisiona lento | ~$5/mo fijo | Media (permite BB con ticket previo) | EU/US/Asia |
| **OVHcloud VPS** | ❌ No (mayormente mensual) | Mensual | API | ~$5/mo | Variable | Global |

**Conclusión**: para replicar el modelo efímero de DO al mismo precio → **Vultr, Linode o Hetzner Cloud**. **Contabo/OVH quedan fuera** para efímero (son VPS mensual fijo: una IP estática reutilizada campaña tras campaña, que termina acumulando el mismo ban que temías).

### 2.1 ¿Cuáles sirven realmente para bug bounty? (aptitud, verificado 2026-09-10)

**El principio que aplica a TODOS** (verificado en AUPs reales): los proveedores serios prohíben escanear sistemas **sin autorización** — no el escaneo en sí. La AUP de Vultr, por ejemplo, prohíbe *"probe, scan, or test the vulnerability of a System… without permission"*. En bug bounty **tienes** permiso del programa sobre el target, así que el escaneo autorizado **no viola la letra del AUP**. Lo que en la práctica te suspende NO es el AUP, sino **cómo el proveedor maneja las quejas de abuso**: no puede verificar tu autorización automáticamente y reacciona a reportes de terceros. Por eso este proyecto usa IPs **efímeras/quemables** (rotar por campaña) + un `policy.json` de scope + `--scope-id`.

Para elegir importa: (a) cómo maneja quejas de abuso (velocidad, si bloquea solo la IP o toda la cuenta), (b) si bloquea puertos de salida, (c) si soporta IP efímera (para que una IP quemada no importe).

| Proveedor | Apto para BB (autorizado)? | Detalle |
|---|---|---|
| **DigitalOcean** | ✅ Sí — baseline del proyecto | Tolerante con IPs efímeras; toda la arquitectura asume quemar la IP por campaña. |
| **Vultr** | ✅ Sí — reemplazo más directo de DO | AUP estándar (prohíbe escaneo *no autorizado*; BB autorizado OK). Horario+API+efímero → IP quemable barata. Muy usado en la comunidad BB. |
| **Linode / Akamai** | ✅ Sí | Modelo y tolerancia similares a Vultr; usado en tooling de BB. |
| **Hetzner Cloud** | ⚠️ Sí, pero es el **más estricto** para este workload | El más barato, pero (reportes de comunidad): plazo de **~6h** para responder quejas por port-scanning, bloqueo rápido de IP, *"no se negocia"*, y **puerto 22 saliente bloqueado** + restringe parte del escaneo saliente. Apto **solo** si mantienes scope estricto y respondes tickets de abuso rápido. Malo para "dejarlo corriendo horas sin supervisión". |
| **Contabo** | ⚠️ Con matiz | Permite BB *con ticket previo*, pero es **mensual/no efímero** → IP estática que acumula bans con el tiempo. Sirve como worker persistente tolerante, no para rotación efímera. |
| **Oracle / Azure / AWS** | ❌ No para el nodo de escaneo | Hyperscalers: requieren **autorización/notificación formal de pentest** y tienen heurísticas de abuso agresivas. Oracle: el propio código lo bloquea (`is_oracle_cloud()` corta capas Scanning+) y su AUP prohíbe originar tráfico a targets. Úsalos para **infra** (coordinador/interactsh), no para escanear. |

**Regla de oro (no negociable):** escanea **solo** targets dentro del scope de un programa que te autoriza; aun así, espera quejas de abuso ocasionales y mantente **disponible para responderlas** — así conservas la cuenta. Autorización del programa ≠ el proveedor lo sabe automáticamente.

**Recomendación para el propósito de este proyecto** (worker de escaneo efímero, presupuesto ajustado): **Vultr o Linode** — apto para BB, modelo efímero horario idéntico a DO, y sin la fricción de abuso de Hetzner. Hetzner solo si el precio manda y aceptas gestionar tickets de abuso activamente.

### 2.2 Más clones horarios + criterios OPSEC (verificado 2026-09-10)

**Realidad honesta (trilema):** no existe un VPS mainstream que sea a la vez (1) "escaneo completamente libre / sin restricciones", (2) barato y **por hora + API**, y (3) con **OPSEC/jurisdicción profesional**. Todo proveedor horario serio (Vultr, Linode, Scaleway, UpCloud, Kamatera, Exoscale, DO) tiene el **mismo AUP estándar**: escaneo solo **autorizado**, y reacciona a quejas de abuso. La tolerancia "sin restricciones" vive en hosts *bulletproof*/offshore que son **mensuales (no horarios)**, con IPs de mala reputación (tus scans llegan pre-bloqueados por los targets) y riesgo OPSEC/legal — **no recomendados** para este proyecto, que está diseñado para testing **autorizado** (`policy.json` + `--scope-id` + approval gates). El objetivo realista es: **tolerante-a-testing-autorizado + horario + buena jurisdicción**, no "escanear lo que sea".

Otros clones horarios (además de Vultr/Linode/Hetzner de §2) — **verifica AUP y precio actual antes de comprometer**:

| Proveedor | ¿Horario + API? | Jurisdicción | Nota OPSEC / AUP |
|---|---|---|---|
| **Scaleway** | ✅ Sí — horario/por-segundo, API + `scw` (verificado) | EU (Francia/NL/Polonia, GDPR) | AUP estándar (escaneo autorizado). Su *Intrusion Testing Agreement* (ventana Lun-Jue + aprobación previa) regula testear **la infra de Scaleway**, NO tu testing saliente autorizado de terceros. Instancias DEV baratas. |
| **UpCloud** | ✅ Sí (horario, API) — *verificar* | Finlandia/EU + global | AUP estándar. Tier ~$5/mo. |
| **Kamatera** | ✅ Sí (horario, API) — *verificar* | Global (US/EU/Asia) | AUP estándar. Barato, trial 30 días. |
| **Exoscale** | ✅ Sí (horario, API) — *verificar* | Suiza/EU | Jurisdicción de privacidad fuerte (OPSEC+). AUP estándar. |
| **BuyVM / Frantech** | ❌ Mensual (no horario) | Canadá / Luxemburgo | Históricamente muy tolerante, pero **no efímero/horario** → no encaja el modelo de este proyecto. Solo mención. |

**Criterios OPSEC profesionales para elegir el nodo de escaneo** (derivados de los principios §5 de `docs/deployment/00_OVERVIEW.md`):
1. **IP efímera/quemable** — rotar por campaña; horario+API lo permite. Una IP quemada no debe importar.
2. **Sin fuga de atribución** — droplet sin datos personales, sin `User-Agent` identificable, SSH keys no reutilizadas entre nodos, sin `whois` que apunte a ti (principio §5.10).
3. **Binds solo por Tailscale** — nada de servicios de gestión expuestos a Internet; gestión vía malla privada (§5.2).
4. **Kill-switch / auto-destroy** — el nodo se destruye al terminar la campaña (el modelo efímero de DO, TTL < 6h — §5.3).
5. **Jurisdicción consciente** — dónde viven el proveedor y los datos; EU/Suiza dan garantías de privacidad más fuertes.
6. **Higiene de cuenta** — cuenta dedicada + MFA por hardware; separada de tu identidad principal. (Bug bounty legítimo NO requiere anonimato total; el objetivo es **separación limpia**, no ocultamiento — sobre-anonimizar levanta sospechas.)

---

## 3. ⚠️ Caveat de código CRÍTICO — el auto-provisioning está hardcodeado a DO

El spin-up/kill-switch automático vive en `src/infrastructure/digital_ocean.rs` (`create_worker_droplet()`, `destroy_all_ephemeral_droplets()`), lee `DIGITALOCEAN_TOKEN`, y llama a la API de DO. **No existe adapter de Vultr/Linode/Hetzner.** Dos caminos:

1. **Efímero manual** (sin escribir código): creas/destruyes la instancia con el CLI del proveedor (`vultr-cli`, `hcloud`, `linode-cli`) y corres `redteam_rust_core --worker --postgres-url <box2>` sobre ella. Ganas la IP fresca; pierdes el kill-switch/auto-spawn nativo.
2. **Adapter nuevo** (código): módulo espejo de `digital_ocean.rs` para el proveedor elegido (Vultr es el clon más fiel de DO → el port más directo). Requiere implementar create/list/destroy contra su API + `provider`/token configurables en vez de `DIGITALOCEAN_TOKEN` hardcodeado.

---

## 4. Presupuesto — efímero ≠ mensual, y ≠ gratis

- Con facturación **por hora** no pagas $5/mes: pagas por hora de escaneo. Campaña de ~4h en Vultr/Linode ≈ **$0.03–0.04**. Unas pocas campañas/mes = **menos de $1**.
- **Pero requiere tarjeta o crédito prepago.** Efímero es el modelo legítimo más barato, no gratis.
- **Cuando no hay presupuesto**, el único fallback legítimo para el rol de escaneo es tu **PC de casa como worker temporal** (vía `--worker` sobre Tailscale), aceptando el riesgo de IP residencial y **solo para escaneos livianos** (recon, no `nmap -p- --min-rate` ni masscan).

### ❌ NO usar: "VPS gratis para estudiantes" dudosos (verificado 2026-09-09)
- **GratisVPS.net** — patrón de estafa confirmado (trust score bajo, esquema de clic en ads, el VPS "nunca se activa"). Fuentes: Trustpilot, Scam-Detector, Scamadviser, Gridinsoft.
- **FreeVPS.edu.pl** — sin ningún respaldo independiente; todos los resultados son contenido del propio sitio. No verificable. No entregues correo institucional ni datos reales de bug bounty ahí.

Oracle Always-Free y Azure for Students son las únicas ofertas "gratis" legítimas — pero para **infra** (coordinador / interactsh), **no para el nodo de escaneo**.

---

## 5. Nota de higiene (aplicada 2026-09-10)

Se eliminó una credencial de BD hardcodeada (`postgres://osintuser:<password>@…`) de `src/utils/config.rs` y `src/utils/api_budget.rs`; el default ahora es `postgres://osintuser@localhost:5432/osintdb` (sin contraseña embebida). Todo token de proveedor (`DIGITALOCEAN_TOKEN`, `GH_TOKEN`, `INTERACTSH_TOKEN`) ya se lee de variables de entorno — no hay secretos de proveedor hardcodeados en el código.

---

## 6. Referencias

- `docs/deployment/06_DO_EPHEMERAL_WORKERS.md` — ciclo de vida del worker efímero + cloud-init (tamaño, tools, tags).
- `docs/deployment/00_OVERVIEW.md` — topología completa (4 boxes + workers) y modelo de amenazas.
- `docs/deployment/HYBRID_DEPLOYMENT_TOPOLOGY.md` — plan de gasto por proveedor / burn plan.
- `src/infrastructure/digital_ocean.rs` — provisioning actual (hardcodeado a DO; punto de extensión para un adapter nuevo).

### Fuentes externas (verificadas 2026-09-10 — los términos cambian, re-verifica)
- Vultr Use Policy — <https://www.vultr.com/legal/use-policy/> (prohíbe escaneo *sin permiso*; el autorizado no viola la letra).
- Hetzner System Policies — <https://www.hetzner.com/legal/system-policies/> (política oficial). Especificidades de manejo de abuso (plazo ~6h, puerto 22 saliente bloqueado) provienen de **reportes de comunidad** (LowEndTalk, redes sociales), no de política oficial — trátalos como indicativos.
- Verificación de "VPS gratis" descartados: GratisVPS.net (Trustpilot / Scam-Detector / Scamadviser / Gridinsoft — patrón de estafa) y FreeVPS.edu.pl (sin respaldo independiente).
- Scaleway — facturación horaria confirmada; *Intrusion Testing Agreement* (<https://www-uploads.scaleway.com/SCW_EXT_007_Accord_Pentest_Clients_Scaleway_EN_v_1_2_62d4ec1eab.pdf>) aplica a testear la infra de Scaleway, no al testing saliente autorizado de terceros.
- UpCloud / Kamatera / Exoscale — facturación horaria + API por conocimiento general; **AUP y precio no verificados individualmente esta sesión** — confirmar en el sitio de cada uno antes de usar.
