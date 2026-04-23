# 🔱 Roadmap: Mission Control Panel — Checklist de Implementación

> **Meta**: Lanzar misiones Bug Bounty desde la web, sin tocar la terminal.
> **Tiempo estimado**: 3-5 horas en una sola sesión.

---

## ✅ FASE 1 — Login Page (15 min)

### Archivos a crear/modificar:
- [ ] `src/core/web/assets/login.html` — Página de login (input token + botón)
- [ ] `src/core/web/assets.rs` — Servir `/login` sin autenticación previa

### Comportamiento:
- El operador pega el token de `workspace/logs/dashboard.token`
- Se guarda en `sessionStorage` del browser
- Redirige a `/dashboard` si válido (`GET /api/v1/stats` retorna 200)

---

## ✅ FASE 2 — Engine Queue + API (1 hora)

### 2A — Nuevas estructuras (`src/core/web/models.rs`)

```rust
// AÑADIR al final del archivo
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MissionRequest {
    pub target: String,
    pub program_name: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub profile: String,          // "passive" | "recon" | "standard" | "aggressive" | "autonomous"
    pub stealth: bool,
    pub vuln_scan: bool,
    pub oob_enabled: bool,
    pub use_swarm: bool,
    pub max_concurrency: u8,
    pub notes: String,
}
```

### 2B — Canal en `DashboardState` (`src/core/web/state.rs`)

```rust
// AÑADIR al struct DashboardState
pub mission_tx: Option<Arc<tokio::sync::mpsc::Sender<MissionRequest>>>,
```

### 2C — Handler POST (`src/core/web/handlers.rs`)

```rust
// AÑADIR al final
pub async fn submit_mission(
    _auth: ValidatedOperator,
    State(state): State<Arc<DashboardState>>,
    Json(req): Json<MissionRequest>,
) -> impl axum::response::IntoResponse {
    if let Some(tx) = &state.mission_tx {
        match tx.send(req).await {
            Ok(_) => (axum::http::StatusCode::ACCEPTED, "Mission queued").into_response(),
            Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Engine not ready").into_response(),
        }
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Mission channel not configured").into_response()
    }
}
```

### 2D — Registrar ruta (`src/core/web/mod.rs`)

```rust
// AÑADIR en el Router
.route("/api/v2/missions", post(handlers::submit_mission))
```

### 2E — Canal en `main.rs`

```rust
// AÑADIR antes de crear el DashboardState
let (mission_tx, mut mission_rx) = tokio::sync::mpsc::channel::<MissionRequest>(32);

// AÑADIR spawn listener del canal (después de inicializar engine)
tokio::spawn(async move {
    while let Some(mission) = mission_rx.recv().await {
        let target = build_target_from_mission(&mission);
        engine_clone.run_mission(target, &mission).await.ok();
    }
});

// Al construir dashboard_state, pasar el sender:
// mission_tx: Some(Arc::new(mission_tx)),
```

---

## ✅ FASE 3 — Formulario Web en `index.html` (1 hora)

```html
<!-- AÑADIR en el HTML del dashboard existente -->
<section id="new-mission">
  <h2>🎯 Launch Mission</h2>
  <form id="missionForm">
    <label>Target Domain</label>
    <input id="target" placeholder="example.com" required />

    <label>Bug Bounty Program</label>
    <input id="program_name" placeholder="HackerOne - PayPal" />

    <label>In-Scope (uno por línea)</label>
    <textarea id="in_scope" placeholder="*.example.com&#10;api.example.com"></textarea>

    <label>Out-of-Scope (uno por línea)</label>
    <textarea id="out_of_scope" placeholder="admin.example.com"></textarea>

    <label>Scan Profile</label>
    <select id="profile">
      <option value="passive">🔍 Passive (Solo OSINT)</option>
      <option value="recon">🗺️ Recon (DNS + Ports)</option>
      <option value="standard" selected>⚡ Standard (OWASP + CVEs)</option>
      <option value="aggressive">💥 Aggressive (Full)</option>
      <option value="autonomous">🤖 Autonomous (AI Swarm)</option>
    </select>

    <label><input type="checkbox" id="stealth" checked /> Stealth Mode</label>
    <label><input type="checkbox" id="vuln_scan" checked /> CVE Scan (Nuclei + NVD)</label>
    <label><input type="checkbox" id="oob_enabled" checked /> OOB Testing (Interactsh)</label>
    <label><input type="checkbox" id="use_swarm" /> Multi-Agent Swarm</label>

    <label>Concurrency: <span id="concurrencyVal">20</span></label>
    <input type="range" id="max_concurrency" min="1" max="100" value="20"
      oninput="document.getElementById('concurrencyVal').textContent = this.value" />

    <label>Operator Notes</label>
    <textarea id="notes" placeholder="Foco en XSS en api. No borrar datos."></textarea>

    <button type="submit">🚀 Launch Mission</button>
  </form>
</section>

<script>
document.getElementById('missionForm').onsubmit = async (e) => {
  e.preventDefault();
  const token = sessionStorage.getItem('dashboard_token');
  const payload = {
    target: document.getElementById('target').value,
    program_name: document.getElementById('program_name').value,
    in_scope: document.getElementById('in_scope').value.split('\n').filter(Boolean),
    out_of_scope: document.getElementById('out_of_scope').value.split('\n').filter(Boolean),
    profile: document.getElementById('profile').value,
    stealth: document.getElementById('stealth').checked,
    vuln_scan: document.getElementById('vuln_scan').checked,
    oob_enabled: document.getElementById('oob_enabled').checked,
    use_swarm: document.getElementById('use_swarm').checked,
    max_concurrency: parseInt(document.getElementById('max_concurrency').value),
    notes: document.getElementById('notes').value,
  };
  const res = await fetch('/api/v2/missions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
    body: JSON.stringify(payload)
  });
  if (res.status === 202) alert('✅ Mission queued!');
  else alert('❌ Error: ' + await res.text());
};
</script>
```

---

## ✅ FASE 4 — HTTPS en Oracle (30 min)

```bash
# 1. Instalar nginx + certbot
sudo apt install nginx certbot python3-certbot-nginx -y

# 2. Obtener certificado (usa tu dominio .me del Student Pack)
sudo certbot --nginx -d tu-dominio.me

# 3. Config nginx: /etc/nginx/sites-available/osint
```

```nginx
server {
    listen 443 ssl;
    server_name tu-dominio.me;

    # (Opcional) Bloquear todo excepto tu IP personal:
    # allow 1.2.3.4;
    # deny all;

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_buffering off;       # Necesario para SSE
        proxy_read_timeout 86400;  # Necesario para SSE
    }
}
```

---

## 📌 Orden de Ejecución en la Sesión

```
1. models.rs   → Añadir struct MissionRequest
2. state.rs    → Añadir campo mission_tx
3. handlers.rs → Añadir fn submit_mission()
4. mod.rs      → Registrar POST /api/v2/missions
5. main.rs     → Crear canal mpsc + spawn listener
6. index.html  → Añadir formulario + JS submit
7. assets.rs   → Servir /login sin auth check
8. cargo build → Verificar compilación
9. nginx       → HTTPS + proxy en Oracle
```

---

## 🧪 Test Rápido

```bash
# Iniciar
./target/release/redteam_rust_core --dashboard 3001

# Leer token
cat workspace/logs/dashboard.token

# Probar endpoint
curl -X POST http://localhost:3001/api/v2/missions \
  -H "Authorization: Bearer TU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","program_name":"Test","in_scope":["*.example.com"],"out_of_scope":[],"profile":"passive","stealth":true,"vuln_scan":false,"oob_enabled":false,"use_swarm":false,"max_concurrency":5,"notes":""}'

# Esperado: HTTP 202 Accepted ✅
```
