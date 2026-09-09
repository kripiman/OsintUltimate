# 🔥 REMEDIACIÓN P0 — Vulnerabilidades Críticas

> **Fecha**: 2026-06-12  
> **Status**: 🔴 BLOQUEANTE para producción  
> **Scope**: tcp_session.rs + sandbox logic + 5 módulos adicionales

---

## 📊 Estadísticas de Violación

```
Total archivos con Command::new: 111
Violaciones críticas identificadas: 7 archivos
  - tcp_session.rs: 3x iptables (P0)
  - sandbox/mod.rs: 1x docker (P1)
  - remote.rs: 1x ssh (P0)
  - source_analyzer.rs: 1x git (P1)
  - gitleaks.rs: 1x tool binary (P2 — dentro de sandbox)
```

---

## 🎯 P0-1: tcp_session.rs — iptables Bypass

### Problema

[tcp_session.rs](src/core/net_evasion/tcp_session.rs) líneas 363, 382, 409:

```rust
// INSEGURO — Bypass completo de StealthExecutor
Command::new("iptables")
    .args(["-A", "OUTPUT", ...])
    .status()
```

**7 controles omitidos**: policy, env_clear, proxy, audit, redaction, PGID, sandbox.

### Solución

**Opción A (Recomendada)**: Inyectar `StealthExecutor` en `TcpSession`

```rust
pub struct TcpSession {
    // ... campos existentes ...
    executor: Arc<StealthExecutor>,
}

impl TcpSession {
    fn add_iptables_rst_drop(..., executor: &StealthExecutor) -> Result<()> {
        let check = executor.spawn("iptables", vec![
            "-C", "OUTPUT",
            "-p", "tcp",
            "--tcp-flags", "RST", "RST",
            "-s", &local_ip.to_string(),
            "-d", &remote_ip.to_string(),
            "--sport", &local_port.to_string(),
            "-j", "DROP",
        ]).await?;
        
        if check.wait().await?.success() {
            return Ok(()); // Ya existe
        }
        
        let add = executor.spawn("iptables", vec![
            "-A", "OUTPUT", // ... mismos args con -A
        ]).await?;
        
        if !add.wait().await?.success() {
            anyhow::bail!("iptables -A failed");
        }
        Ok(())
    }
}
```

**Opción B (Más rápida)**: Validar con `PolicyProvider` directo

```rust
fn add_iptables_rst_drop(
    local_ip: Ipv4Addr, 
    remote_ip: Ipv4Addr, 
    local_port: u16,
    policy: &dyn PolicyProvider,
) -> Result<()> {
    let args = vec!["-A", "OUTPUT", ...];
    policy.validate_command("iptables", &args)?;
    
    let mut cmd = Command::new("iptables");
    cmd.env_clear()
       .env("PATH", std::env::var("PATH").unwrap_or_default())
       .args(args);
    
    let status = cmd.status()?;
    // ... resto
}
```

### Archivos a modificar

1. `src/core/net_evasion/tcp_session.rs`: 
   - Añadir campo `executor: Arc<StealthExecutor>` o `policy: Arc<dyn PolicyProvider>`
   - Modificar 3 funciones: `add_iptables_rst_drop`, `remove_iptables_rst_drop`, y check en `connect()`

2. `src/core/net_evasion/mod.rs`:
   - Inyectar executor/policy en constructor de `TcpSession`

**Esfuerzo**: 1-2 horas  
**Riesgo**: Bajo (cambio local)

---

## 🎯 P0-2: SEC-004 Rec#2 — net_evasion → StrictDocker

### Problema

[sandbox/mod.rs:54](src/core/sandbox/mod.rs#L54) solo chequea categoría, no capabilities:

```rust
let is_exploit = matches!(category, 
    Category::Vulnerability | Category::Windows | Category::Linux
);
```

Herramientas `net_evasion` con categoría `scanner` o `osint` → `FluidLocal` en low-RAM.

### Solución

```rust
pub fn determine_tier(&self, tool: &BlackArchTool) -> ExecutionTier {
    let category = self.map_blackarch_category(&tool.category);
    
    // SEC-004 Rec#2: net_evasion MUST run in StrictDocker
    let requires_strict = matches!(category, 
        Category::Vulnerability | Category::Windows | Category::Linux
    ) || tool.capabilities.iter().any(|cap| matches!(cap, 
        Capability::RawSocket | 
        Capability::PacketForge | 
        Capability::Evasion
    ));
    
    if self.res_mgr.supports_strict_mode() {
        ExecutionTier::StrictDocker
    } else {
        if requires_strict {
            info!("⚠️ Forcing StrictDocker for {} (net_evasion capability)", tool.name);
            ExecutionTier::StrictDocker
        } else {
            ExecutionTier::FluidLocal
        }
    }
}
```

**Pre-requisito**: Verificar que `BlackArchTool.capabilities` incluya enum variants `RawSocket`, `PacketForge`, `Evasion`.

**Esfuerzo**: 30 minutos  
**Riesgo**: Bajo

---

## 🎯 P0-3: Wildcard Fail-Secure

### Problema

[sandbox/mod.rs:80](src/core/sandbox/mod.rs#L80):

```rust
_ => Category::TechnologyStack, // Fail-OPEN
```

Categoría desconocida → no-exploit → `FluidLocal`.

### Solución

```rust
fn map_blackarch_category(&self, cat: &str) -> Category {
    match cat.to_lowercase().as_str() {
        "exploitation" | "cracker" => Category::Vulnerability,
        "scanner" | "fuzzer" => Category::Scanning,
        "osint" | "recon" | "discovery" => Category::Recon,
        "webapp" => Category::SCA,
        "windows" => Category::Windows,
        "linux" => Category::Linux,
        _ => {
            tracing::warn!("⚠️ Unknown BlackArch category '{}', forcing StrictDocker", cat);
            Category::Vulnerability // Fail-SECURE: trata desconocidos como exploits
        }
    }
}
```

**Esfuerzo**: 5 minutos  
**Riesgo**: Cero

---

## 🎯 P1-1: remote.rs SSH Bypass

### Problema

[remote.rs:24](src/core/validation/remote.rs#L24):

```rust
let mut command = Command::new("ssh");
command.args([...]).spawn()?
```

Sin policy, sin env_clear, sin audit.

### Solución

```rust
pub async fn execute(&self, target: &TargetHost, cmd: &str) -> Result<String> {
    // Opción 1: Usar StealthExecutor ya existente
    if let Some(ref executor) = self.executor {
        let child = executor.spawn("ssh", vec![
            "-o", "StrictHostKeyChecking=no",
            &format!("{}@{}", self.username, target.host),
            cmd,
        ]).await?;
        
        let output = child.wait_with_output().await?;
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    
    anyhow::bail!("RemoteExecutor requires StealthExecutor");
}
```

**Cambio**: Añadir campo `executor: Option<Arc<StealthExecutor>>` al struct.

**Esfuerzo**: 30 minutos  
**Riesgo**: Bajo

---

## 🎯 P1-2: sandbox/mod.rs env_clear()

### Problema

[sandbox/mod.rs:232](src/core/sandbox/mod.rs#L232):

```rust
let mut cmd = Command::new("docker");
// No env_clear() — hereda secretos del host
```

### Solución

```rust
let mut cmd = Command::new("docker");
cmd.env_clear()
   .env("PATH", std::env::var("PATH").unwrap_or_default());

cmd.arg("run").arg("--rm")...
```

**También aplicar** en `FluidLocal` (línea 276):

```rust
let mut cmd = Command::new(&tool.name);
cmd.env_clear()
   .env("PATH", std::env::var("PATH").unwrap_or_default())
   .args(sanitized_args)
   .stdout(Stdio::piped())
   .stderr(Stdio::piped());
```

**Esfuerzo**: 10 minutos  
**Riesgo**: Bajo (backwards compatible)

---

## 🎯 P1-3: source_analyzer.rs git

### Problema

[source_analyzer.rs:37](src/core/source_analyzer.rs#L37):

```rust
Command::new("git")
    .args(["clone", url, ...])
    .output()?
```

URL arbitraria sin validación, sin env_clear.

### Solución

```rust
pub async fn clone_repo(&self, url: &str, dest: &Path) -> Result<()> {
    // Validar URL (prevenir file://, git@github pero con payload malicioso)
    if !url.starts_with("https://") && !url.starts_with("git@") {
        anyhow::bail!("Only https:// and git@ URLs allowed");
    }
    
    // Usar executor si disponible, o al menos env_clear
    let output = if let Some(ref executor) = self.executor {
        executor.execute_and_wait("git", vec![
            "clone".to_string(),
            "--depth".to_string(), "1".to_string(),
            url.to_string(),
            dest.to_string_lossy().to_string(),
        ]).await?
    } else {
        let mut cmd = Command::new("git");
        cmd.env_clear()
           .env("PATH", std::env::var("PATH").unwrap_or_default())
           .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
           .output()?;
        
        cmd
    };
    
    if !output.status.success() {
        anyhow::bail!("git clone failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}
```

**Esfuerzo**: 20 minutos  
**Riesgo**: Medio (cambiar API si añades executor)

---

## 📋 Checklist de Deploy

Antes de mergear a `main`:

- [ ] P0-1: `tcp_session.rs` refactorizado con Opción A o B
- [ ] P0-2: `sandbox/mod.rs` chequea `tool.capabilities` para net_evasion
- [ ] P0-3: Wildcard fail-secure implementado
- [ ] Tests: `cargo test --workspace` pasa 100%
- [ ] Clippy: `cargo clippy --all-features` sin warnings
- [ ] Audit: `cargo audit` sin CVEs críticos/altos
- [ ] P1-1, P1-2, P1-3: Opcional pero recomendado antes de v1.0

---

## 🧪 Plan de Testing

### Test 1: tcp_session iptables con PolicyProvider mock

```rust
#[tokio::test]
async fn test_tcp_session_respects_policy() {
    let policy = Arc::new(MockPolicy { allowed: false });
    let executor = StealthExecutor::new(policy, None, false);
    
    let result = TcpSession::connect_with_executor(
        channel, local_ip, remote, executor
    ).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("policy"));
}
```

### Test 2: Sandbox capabilities check

```rust
#[test]
fn test_net_evasion_forces_strict_docker() {
    let tool = BlackArchTool {
        name: "custom_scanner".to_string(),
        category: "scanner".to_string(),
        capabilities: vec![Capability::RawSocket],
    };
    
    let dispatcher = SandboxDispatcher::new(
        SysResourceManager::new(4096) // Low-RAM
    );
    
    assert_eq!(
        dispatcher.determine_tier(&tool),
        ExecutionTier::StrictDocker
    );
}
```

### Test 3: Wildcard unknown category

```rust
#[test]
fn test_unknown_category_fails_secure() {
    let tool = BlackArchTool {
        category: "malicious_custom_xyz".to_string(),
        ..Default::default()
    };
    
    let dispatcher = SandboxDispatcher::new(
        SysResourceManager::new(4096)
    );
    
    let category = dispatcher.map_blackarch_category(&tool.category);
    assert_eq!(category, Category::Vulnerability); // Fail-secure
}
```

---

## 📚 Referencias

- [SEC-004_sandbox_spike.md](docs/security/SEC-004_sandbox_spike.md#L97) — Recommendation #2
- [stealth_opsec.md](docs/stealth_opsec.md#L11) — StealthExecutor mandatory policy
- [ADR-012](docs/ADR-012-AI-CONTEXT-HARDENING.md#L40) — StealthClientBuilder permanent compilation

---

**Owner**: @Senior-Architect  
**Deadline**: Antes de cualquier deploy a producción  
**Status**: 🔴 EN PROGRESO
