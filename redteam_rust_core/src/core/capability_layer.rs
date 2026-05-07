// src/core/capability_layer.rs (NUEVO)
// 🏛️ Capability Layer System - Control de Agresividad de Escaneos
// ⚡ Permite workflows pasivos vs. activos vs. explotación

use serde::{Deserialize, Serialize};

/// Define el nivel de "agresividad" o intrusión de un plugin
/// Esto permite workflows graduales y control sobre riesgos
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScanLayer {
    /// LAYER 0: Passive reconnaissance - Sin tráfico activo
    /// ✅ Seguro
    /// Ejemplos: crt.sh, OSINT, búsqueda en Google, logs públicos
    Passive = 0,
    
    /// LAYER 1: Discovery - Ligero probing, bajo riesgo de detección
    /// ✅ Bajo riesgo
    /// Ejemplos: DNS quering, HTTP HEAD requests, port scanning (ligero)
    Discovery = 1,
    
    /// LAYER 2: Scanning - Escaneo activo, detectable por anomalías
    /// ⚠️ Mediano riesgo
    /// Ejemplos: Nmap intensive, vulnerability scanning, fuzzing
    Scanning = 2,
    
    /// LAYER 3: Verification - Verificación de vulnerabilidades
    /// ⚠️ Alto riesgo - Puede activar alertas
    /// Ejemplos: Intentos de exploit no-destructivos, PoC
    Verification = 3,
    
    /// LAYER 4: Exploitation - Explotación activa, cambios en el sistema
    /// 🔴 Crítico - Alto riesgo de detección y daño
    /// Ejemplos: Reverse shells, injections, malware dropp​ing, persistence
    Exploitation = 4,
    
    /// LAYER 5: PostExploitation - Post-explotación y movimiento lateral
    /// 🔴 Crítico - Impacto severo
    /// Ejemplos: Privilege escalation, data exfiltration, AD enumeration
    PostExploitation = 5,
}

impl std::str::FromStr for ScanLayer {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "passive" => Ok(Self::Passive),
            "discovery" => Ok(Self::Discovery),
            "scanning" => Ok(Self::Scanning),
            "verification" => Ok(Self::Verification),
            "exploitation" => Ok(Self::Exploitation),
            "post-exploitation" | "postexploitation" => Ok(Self::PostExploitation),
            _ => Err(format!("Invalid scan layer: {}", s)),
        }
    }
}

impl ScanLayer {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Passive => "Passive OSINT - No active traffic",
            Self::Discovery => "Discovery - Light probing",
            Self::Scanning => "Active scanning - Detectable",
            Self::Verification => "Verification - High risk of detection",
            Self::Exploitation => "Exploitation - System-altering actions",
            Self::PostExploitation => "Post-Exploitation - Severe impact",
        }
    }
    
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::Verification | Self::Exploitation | Self::PostExploitation)
    }
    
    pub fn risk_score(&self) -> u8 {
        match self {
            Self::Passive => 0,
            Self::Discovery => 15,
            Self::Scanning => 35,
            Self::Verification => 65,
            Self::Exploitation => 90,
            Self::PostExploitation => 100,
        }
    }
}

/// Configuración de máximo nivel de agresividad permitido
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScanLayerPolicy {
    pub max_layer: ScanLayer,
    pub require_approval_for_layer_3_plus: bool,
    pub require_approval_for_layer_4_plus: bool,
    pub require_approval_for_layer_5: bool,
}

impl ScanLayerPolicy {
    pub fn preset_passive() -> Self {
        Self {
            max_layer: ScanLayer::Passive,
            require_approval_for_layer_3_plus: false,
            require_approval_for_layer_4_plus: false,
            require_approval_for_layer_5: false,
        }
    }
    
    pub fn preset_discovery_only() -> Self {
        Self {
            max_layer: ScanLayer::Discovery,
            require_approval_for_layer_3_plus: false,
            require_approval_for_layer_4_plus: false,
            require_approval_for_layer_5: false,
        }
    }
    
    pub fn preset_audit() -> Self {
        Self {
            max_layer: ScanLayer::Scanning,
            require_approval_for_layer_3_plus: false,
            require_approval_for_layer_4_plus: false,
            require_approval_for_layer_5: false,
        }
    }
    
    pub fn preset_authorized_red_team() -> Self {
        Self {
            max_layer: ScanLayer::PostExploitation,
            require_approval_for_layer_3_plus: true,
            require_approval_for_layer_4_plus: true,
            require_approval_for_layer_5: true,
        }
    }
    
    pub fn is_plugin_allowed(&self, plugin_layer: ScanLayer) -> bool {
        plugin_layer <= self.max_layer
    }
    
    pub fn needs_approval(&self, plugin_layer: ScanLayer) -> bool {
        match plugin_layer {
            ScanLayer::Verification => self.require_approval_for_layer_3_plus,
            ScanLayer::Exploitation => self.require_approval_for_layer_4_plus,
            ScanLayer::PostExploitation => self.require_approval_for_layer_5,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scan_layer_ordering() {
        assert!(ScanLayer::Passive < ScanLayer::Discovery);
        assert!(ScanLayer::Discovery < ScanLayer::Scanning);
        assert!(ScanLayer::PostExploitation > ScanLayer::Exploitation);
    }
    
    #[test]
    fn test_approval_policy() {
        let policy = ScanLayerPolicy::preset_audit();
        assert!(policy.is_plugin_allowed(ScanLayer::Scanning));
        assert!(!policy.is_plugin_allowed(ScanLayer::Exploitation));
    }
}
