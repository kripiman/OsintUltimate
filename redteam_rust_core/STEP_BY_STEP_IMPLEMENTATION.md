# 📋 IMPLEMENTACIÓN PASO A PASO - OsintUltimate v3.0

## Fase 0: Preparación (Semana 0)

### 0.1 Reorganizar estructura de carpetas

```bash
cd redteam_rust_core

# Crear la nueva estructura de categorías
mkdir -p src/plugins/reconnaissance/{osint,passive,active}
mkdir -p src/plugins/enumeration/{web,network,cloud}
mkdir -p src/plugins/exploitation/{web,network,wireless,mobile,lateral_movement}
mkdir -p src/plugins/privilege_escalation
mkdir -p src/plugins/persistence
mkdir -p src/plugins/detection_evasion
mkdir -p src/plugins/intelligence
mkdir -p src/plugins/verification
mkdir -p src/plugins/compliance
mkdir -p src/plugins/reporting

# Nueva estructura de core
mkdir -p src/core/workflows
mkdir -p src/core/ai_analysis
mkdir -p src/utils/reporting/{html,sarif,csv}
mkdir -p src/utils/vault

# Mover plugins existentes (PARCIALMENTE MOSTRADO)
# OSINT
mv src/plugins/osint.rs src/plugins/reconnaissance/osint/mod.rs
mv src/plugins/unfinder.rs src/plugins/reconnaissance/osint/subfinder.rs
mv src/plugins/amass.rs src/plugins/reconnaissance/osint/amass.rs
mv src/plugins/uncover.rs src/plugins/reconnaissance/osint/uncover.rs

# Passive
mv src/plugins/wayback.rs src/plugins/reconnaissance/passive/wayback.rs
sv src/plugins/gitleaks.rs src/plugins/reconnaissance/passive/gitleaks.rs
mv src/plugins/searchsploit.rs src/plugins/reconnaissance/passive/searchsploit.rs

# Active
mv src/plugins/dnsx.rs src/plugins/reconnaissance/active/dnsx.rs
mv src/plugins/httpx.rs src/plugins/reconnaissance/active/httpx.rs
mv src/plugins/naabu.rs src/plugins/reconnaissance/active/naabu.rs

# Web Enumeration
mv src/plugins/ffuf.rs src/plugins/enumeration/web/ffuf.rs
mv src/plugins/feroxbuster.rs src/plugins/enumeration/web/feroxbuster.rs
mv src/plugins/arjun.rs src/plugins/enumeration/web/arjun.rs
mv src/plugins/katana.rs src/plugins/enumeration/web/katana.rs

# Network Enumeration
mv src/plugins/rustscan.rs src/plugins/enumeration/network/rustscan.rs
mv src/plugins/nmap.rs src/plugins/enumeration/network/nmap.rs
# TODO: Add nmap_async.rs

# Cloud Enumeration
mv src/plugins/cloudenum.rs src/plugins/enumeration/cloud/cloudenum.rs
mv src/plugins/cloudfox.rs src/plugins/enumeration/cloud/cloudfox.rs
mv src/plugins/cloudbrute.rs src/plugins/enumeration/cloud/cloudbrute.rs

# Web Exploitation
mv src/plugins/sqlmap.rs src/plugins/exploitation/web/sqlmap.rs
mv src/plugins/wapiti.rs src/plugins/exploitation/web/wapiti.rs
mv src/plugins/dalfox.rs src/plugins/exploitation/web/dalfox.rs
# NEW: commix.rs, webshell_upload.rs

# Network Exploitation
mv src/plugins/hydra.rs src/plugins/exploitation/network/hydra.rs
mv src/plugins/netexec.rs src/plugins/exploitation/network/netexec.rs
mv src/plugins/impacket.rs src/plugins/exploitation/network/impacket.rs
mv src/plugins/responder.rs src/plugins/exploitation/network/responder.rs
mv src/plugins/petitpotam.rs src/plugins/exploitation/network/petitpotam.rs
# NEW: zerologon.rs, printnightmare.rs, samaccountname_spoofing.rs

# ... etc

# Mover core modules nuevos
mv IMPLEMENTATION_GUIDE_V3.md src/core/
```

### 0.2 Actualizar `src/plugins/mod.rs`

```rust
// src/plugins/mod.rs (REFACTORIZADO COMPLETO)

// Reconnaissance
pub mod reconnaissance;
pub use reconnaissance::*;

// Enumeration
pub mod enumeration;
pub use enumeration::*;

// Exploitation
pub mod exploitation;
pub use exploitation::*;

// Privilege Escalation
pub mod privilege_escalation;
pub use privilege_escalation::*;

// Persistence
pub mod persistence;
pub use persistence::*;

// Detection Evasion
pub mod detection_evasion;
pub use detection_evasion::*;

// Intelligence
pub mod intelligence;
pub use intelligence::*;

// Verification
pub mod verification;
pub use verification::*;

// Compliance
pub mod compliance;
pub use compliance::*;

// Reporting
pub mod reporting;
pub use reporting::*;

// ============ PLUGIN TRAIT ============

use async_trait::async_trait;
use crate::models::{TargetHost, Finding};
use crate::core::capability_layer::ScanLayer;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    PortScanning,
    ServiceDiscovery,
    VulnerabilityScanning,
    WebFuzzing,
    SecretDiscovery,
    CloudAudit,
    ActiveDirectory,
    OsintDiscovery,
    SubdomainEnumeration,
    HistoricalRecon,
    InfrastructureAudit,
    ConfigAudit,
    IAMAssessment,
    SCA,
    SecurityAuditing,
    PrivilegeEscalation,
    LateralMovement,
    Persistence,
    CommandExecution,
    CredentialDumping,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub risk_level: RiskLevel,
    pub expected_duration: std::time::Duration,
    pub capabilities: Vec<Capability>,
    pub layer: ScanLayer,  // ← NUEVO
}

#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    fn metadata(&self) -> PluginMetadata;
    fn name(&self) -> &'static str;
    fn layer(&self) -> ScanLayer;  // ← NUEVO
    async fn scan(&self, target: &mut TargetHost) -> Result<()>;
}
```

---

## Fase 1-2: TIER 0 Plugins (Semanas 1-2)

### 1.1 Registrar nuevos plugins en `src/core/mod.rs`

```rust
// src/core/mod.rs (ADD)
pub mod capability_layer;
pub mod approval_gate;
pub mod workflows;
pub mod ai_analysis;

pub use capability_layer::{ScanLayer, ScanLayerPolicy};
pub use approval_gate::{ApprovalGate, User, UserRole};
```

### 1.2 Actualizar `Cargo.toml` con dependencias TIER 0

```toml
[dependencies]
# Nuevas dependencias para TIER 0
uuid = { version = "1.0", features = ["v4", "serde"] }
urlencoding = "2.1"

# Async utilities
async-stream = "0.3.6"

# Mobile & frida (para futuro)
# frida = "0.13"  # Commented for now
```

### 1.3 Implementación de Commix

Ya incluida en `src/plugins/exploitation/web/commix.rs`

**Checklist**:
- [ ] Crear archivo
- [ ] Implementar trait `ScannerPlugin`
- [ ] Tests unitarios
- [ ] Integrar en orchestrator

### 1.4 Implementación de PrivEsc-Hunter

Ya incluida en `src/plugins/privilege_escalation/privesc_hunter.rs`

**Checklist**:
- [ ] Crear archivo
- [ ] Windows API integration (via `winapi` crate)
- [ ] Registry scanning helper
- [ ] Tests unitarios

### 1.5 Implementación de Capability Layers

Ya incluida en `src/core/capability_layer.rs` y `src/core/approval_gate.rs`

---

## Fase 3-4: TIER 1 Plugins (Semanas 3-4)

### 3.1 Hashcat GPU Integration

```rust
// src/plugins/exploitation/wireless/hashcat_gpu.rs
use async_trait::async_trait;
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayer;
use crate::models::{TargetHost, Finding, Evidence};
use anyhow::Result;

pub struct HashcatGpuScanner {
    wordlist_path: String,
    gpu_id: u8,
    rules: Vec<String>,
}

#[async_trait]
impl ScannerPlugin for HashcatGpuScanner {
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: "HashcatGPU",
            description: "GPU-accelerated password cracking (PMKID, WPA2, etc.)",
            risk_level: crate::plugins::RiskLevel::High,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: vec![
                crate::plugins::Capability::CommandExecution,
                crate::plugins::Capability::CredentialDumping,
            ],
            layer: ScanLayer::Exploitation,
        }
    }
    
    fn name(&self) -> &'static str {
        "HashcatGPU"
    }
    
    fn layer(&self) -> ScanLayer {
        ScanLayer::Exploitation
    }
    
    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // Implementar detección de hashes PMKID/WPA2
        // Llamar a hashcat para cracking
        Ok(())
    }
}
```

### 3.2 ScoutSuite Cloud Auditor

```rust
// src/plugins/enumeration/cloud/scoutsuite.rs
use async_trait::async_trait;
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayer;

pub struct ScoutSuiteScanner {
    aws_profiles: Vec<String>,
    azure_subscriptions: Vec<String>,
    gcp_projects: Vec<String>,
}

#[async_trait]
impl ScannerPlugin for ScoutSuiteScanner {
    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: "ScoutSuite",
            description: "Multi-cloud security auditing (AWS, Azure, GCP)",
            risk_level: crate::plugins::RiskLevel::Low,
            expected_duration: std::time::Duration::from_secs(600),
            capabilities: vec![crate::plugins::Capability::CloudAudit, crate::plugins::Capability::IAMAssessment],
            layer: ScanLayer::Scanning,
        }
    }
    
    fn name(&self) -> &'static str {
        "ScoutSuite"
    }
    
    fn layer(&self) -> ScanLayer {
        ScanLayer::Scanning
    }
    
    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // Escanear múltiples cuentas cloud
        // Reportar misconfiguraciones de IAM
        Ok(())
    }
}
```

### 3.3 Frida Mobile Instrumentation

```rust
// src/plugins/exploitation/mobile/frida.rs
use async_trait::async_trait;
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayer;

pub struct FridaScanner {
    target_package: String,
    scripts_dir: String,
}

#[async_trait]
impl ScannerPlugin for FridaScanner {
    fn name(&self) -> &'static str {
        "Frida"
    }
    
    fn layer(&self) -> ScanLayer {
        ScanLayer::PostExploitation
    }
    
    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // Dynamic instrumentation de apps móviles
        // Hook APIs críticas
        // Extraer secrets
        Ok(())
    }
}
```

---

## Fase 5-6: TIER 2 Plugins (Semanas 5-6)

### 5.1 Krbrelay (Kerberos Relay)

```rust
// src/plugins/exploitation/network/krbrelay.rs
use async_trait::async_trait;
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayer;

pub struct KbrelayScanner {
    listen_port: u16,
    target_service: String,
}

#[async_trait]
impl ScannerPlugin for KbrelayScanner {
    fn name(&self) -> &'static str {
        "KbreLay"
    }
    
    fn layer(&self) -> ScanLayer {
        ScanLayer::Exploitation
    }
    
    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // Implementar Kerberos relay attack
        // Interceptar NTLM/Kerberos auth
        // Obtener acceso como usuario autenticado
        Ok(())
    }
}
```

### 5.2 Anti-EDR Evasion Kit

```rust
// src/plugins/detection_evasion/anti_edr.rs
use async_trait::async_trait;
use crate::plugins::ScannerPlugin;
use crate::core::capability_layer::ScanLayer;

pub struct AntiEDRScanner;

#[async_trait]
impl ScannerPlugin for AntiEDRScanner {
    fn name(&self) -> &'static str {
        "AntiEDR"
    }
    
    fn layer(&self) -> ScanLayer {
        ScanLayer::Detection Evasion
    }
    
    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // Detectar EDR agents activos
        // Técnicas de bypass:
        //  - Code cave injection
        //  - Usermode hooking bypass
        //  - Memory manipulation
        Ok(())
    }
}
```

---

## Fase 7-8: Inteligencia Avanzada (Semanas 7-8)

### 7.1 Global Context + Attack Graphs

```rust
// src/core/ai_analysis/global_context.rs
use dashmap::DashMap;
use std::sync::Arc;
use petgraph::graph::{Graph, NodeIndex};

pub struct GlobalContext {
    /// Todas las máquinas/servicios descubiertos
    services: DashMap<String, ServiceInfo>,
    
    /// Grafos de ataque
    attack_graphs: Arc<Graph<AttackNode, AttackEdge>>,
    
    /// Correlaciones automáticas
    correlations: DashMap<(FindingId, FindingId), CorrelationType>,
    
    /// MITRE ATT&CK mapping
    mitre_mapper: Arc<MitreMapper>,
}

impl GlobalContext {
    pub fn correlate_findings(&self, findings: Vec<Finding>) -> Vec<AttackChain> {
        // Análisis automático de correlaciones
        // Construcción de cadenas de ataque
        // Cálculo de riesgo acumulado
        Vec::new()
    }
}
```

### 7.2 MITRE ATT&CK Framework Mapper

```rust
// src/core/ai_analysis/mitre_mapper.rs
pub struct MitreMapper {
    tactics: HashMap<String, Vec<Technique>>,
}

impl MitreMapper {
    pub fn map_finding(&self, finding: &Finding) -> Vec<String> {
        // Mapear hallazgo a técnicas MITRE
        // Ej: "SQL Injection" -> ["T1190", "T1047"]
        Vec::new()
    }
    
    pub fn generate_heatmap(&self, findings: &[Finding]) -> MitreHeatmap {
        // Generar visualización de tácticas cubiertas
        MitreHeatmap::default()
    }
}
```

---

## Fase 9-10: Reportes Profesionales (Semanas 9-10)

### 9.1 SARIF Export

```rust
// src/utils/reporting/sarif.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    pub runs: Vec<Run>,
}

pub fn export_to_sarif(findings: &[Finding]) -> SarifReport {
    // Convertir findings a formato SARIF 2.1
    // Compatible con Azure DevOps, GitHub, GitLab
    SarifReport {
        version: "2.1.0".to_string(),
        runs: Vec::new(),
    }
}
```

### 9.2 Advanced HTML Reports

```rust
// src/utils/reporting/html.rs
pub fn generate_professional_html(
    findings: &[Finding],
    mitre_data: Option<&MitreHeatmap>,
    compliance_data: Option<&ComplianceMapping>,
) -> String {
    // Generar reportes HTML de nivel ejecutivo
    // Incluir: resumen, cadenas de ataque, MITRE heatmap, recomendaciones
    String::new()
}
```

---

## Fase 11-12: Testing + Deployment (Semanas 11-12)

### 11.1 Integration Tests

```bash
# tests/integration_tests.rs
cargo test --test '*'
```

### 11.2 Docker Config

```dockerfile
# Dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm
RUN apt-get update && apt-get install -y \
    nmap sqlmap metasploit-framework git \
    && rm -rf /var/lib/apt/lists/{apt,dpkg,cache,log} /tmp/* /var/tmp/*

COPY --from=builder /app/target/release/redteam_rust_core /usr/local/bin/

ENTRYPOINT ["redteam_rust_core"]
```

### 11.3 CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI/CD

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Run tests
        run: cargo test --release
      - name: Security audit
        run: cargo audit
      - name: Build Docker image
        run: docker build -t osintultimate:latest .
```

---

## Checklist Final

- [ ] Reorganizar estructura de plugins
- [ ] Implementar Capability Layers
- [ ] Implementar Approval Gate
- [ ] Agregar Commix scanner
- [ ] Agregar PrivEsc-Hunter
- [ ] Integrar Hashcat GPU
- [ ] Integrar ScoutSuite
- [ ] Integrar Frida
- [ ] Implementar Global Context
- [ ] Implementar MITRE Mapper
- [ ] Generar SARIF reports
- [ ] Generar HTML reports
- [ ] Tests + Coverage > 80%
- [ ] Docker image
- [ ] CI/CD pipeline
- [ ] Documentación completa
- [ ] Ejemplos de workflows

---

## Comandos Para Empezar AHORA

```bash
# 1. Crear estructura base
cd redteam_rust_core
mkdir -p src/plugins/reconnaissance/{osint,passive,active}
mkdir -p src/plugins/enumeration/{web,network,cloud}
mkdir -p src/plugins/exploitation/{web,network}
mkdir -p src/core

# 2. Copiar archivos nuevos
cp /tmp/capability_layer.rs src/core/
cp /tmp/approval_gate.rs src/core/
cp /tmp/commix.rs src/plugins/exploitation/web/
cp /tmp/privesc_hunter.rs src/plugins/privilege_escalation/

# 3. Actualizar Cargo.toml
vim Cargo.toml
# Agregar: uuid, urlencoding, petgraph

# 4. Recompil + test
cargo build --release
cargo test

# 5. Usar nuevas capas
./target/release/redteam_rust_core \
  -t target.com \
  --max-layer scanning \
  --approval-threshold 80 \
  --user "red_team_1" \
  --role red_team_full
```

¡Listo! Tienes tu hoja de ruta. 🚀
