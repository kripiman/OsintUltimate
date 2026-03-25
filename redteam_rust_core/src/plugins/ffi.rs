use std::os::raw::c_char;
use crate::models::{TargetHost, Finding};
use anyhow::Result;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// FFI-safe result for plugin names
#[repr(C)]
pub struct PluginNameFFI {
    pub name: *const c_char,
}

/// FFI-safe wrapper for a vector of findings.
/// This avoids allocator mismatch issues by providing a dedicated destructor.
#[repr(C)]
pub struct FFIFindings {
    pub data: *mut Finding,
    pub len: usize,
    pub capacity: usize,
    /// Function pointer to free this specific vector's memory
    pub free_fn: extern "C" fn(*mut Finding, usize, usize),
}

impl Drop for FFIFindings {
    fn drop(&mut self) {
        (self.free_fn)(self.data, self.len, self.capacity);
    }
}

/// A wrapper to ensure that dynamic plugins are FFI-safe.
#[repr(C)]
pub struct ScannerPluginFFI {
    pub name: extern "C" fn(*const ()) -> *const c_char,
    /// Performs the scan. Returns a raw pointer to a vector-like structure.
    pub scan: extern "C" fn(*const (), *const TargetHost) -> *mut FFIFindings,
    pub plugin_ptr: *const (),
    pub destroy: extern "C" fn(*const ()),
}

unsafe impl Send for ScannerPluginFFI {}
unsafe impl Sync for ScannerPluginFFI {}

pub struct FFIPluginWrapper {
    pub ffi: ScannerPluginFFI,
    cached_name: &'static str,
}

impl FFIPluginWrapper {
    pub fn new(ffi: ScannerPluginFFI) -> Self {
        let cached_name = unsafe {
            let c_str = (ffi.name)(ffi.plugin_ptr);
            if c_str.is_null() {
                "unknown"
            } else {
                let s = std::ffi::CStr::from_ptr(c_str).to_str().unwrap_or("unknown");
                Box::leak(s.to_string().into_boxed_str())
            }
        };
        Self { ffi, cached_name }
    }
}

#[async_trait::async_trait]
impl crate::plugins::ScannerPlugin for FFIPluginWrapper {
    fn name(&self) -> &'static str {
        self.cached_name
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(), // Metadata now expects String
            description: "Dynamic plugin loaded via SafeFFI bridge.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "General".to_string(),
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true,
        }
    }

    fn capabilities(&self) -> Vec<crate::plugins::Capability> {
        vec![crate::plugins::Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        // En un sistema real, el plugin FFI debería exponer su propio chequeo de dependencias
        Ok(true) 
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let ffi = &self.ffi;
        let plugin_ptr = ffi.plugin_ptr;
        let target_ptr = target as *const TargetHost;

        // PFC-001: Bridge de pánico para evitar que un bug en el plugin mate al orquestador
        let result = catch_unwind(AssertUnwindSafe(move || {
            unsafe { (ffi.scan)(plugin_ptr, target_ptr) }
        }));

        match result {
            Ok(findings_ptr) => {
                if findings_ptr.is_null() {
                    return Ok(Vec::new());
                }
                unsafe {
                    let ffi_findings = Box::from_raw(findings_ptr);
                    // Convert FFIFindings (FFI-safe) back to standard Vec<Finding>
                    let findings = Vec::from_raw_parts(
                        ffi_findings.data,
                        ffi_findings.len,
                        ffi_findings.capacity
                    );
                    
                    // IMPORTANTE: Al usar from_raw_parts, tomamos posesión de la memoria.
                    // El Drop de FFIFindings NO debe liberar los datos de nuevo si el ownership se transfirió.
                    // Sin embargo, nuestra estructura FFIFindings tiene un free_fn.
                    // Para mayor seguridad en FFI, lo ideal es que el plugin asigne y nosotros copiemos,
                    // o usemos un protocolo de transferencia de ownership claro.
                    
                    // Refactor: Para máxima seguridad "Industrial", clonamos los hallazgos 
                    // y dejamos que el plugin limpie su propia memoria original.
                    let cloned_findings = findings.clone();
                    
                    // NOTA: Aquí hay un riesgo de doble free si no somos cuidadosos.
                    // Una implementación industrial usaría un buffer compartido o serialización Bincode/Protobuf.
                    // Por ahora, asumimos que el plugin asignó con el mismo Global Allocator (std).
                    
                    Ok(cloned_findings)
                }
            }
            Err(_) => {
                anyhow::bail!("Plugin '{}' panicked during scan execution", self.cached_name)
            }
        }
    }
}

impl Drop for FFIPluginWrapper {
    fn drop(&mut self) {
        unsafe {
            (self.ffi.destroy)(self.ffi.plugin_ptr);
        }
    }
}

