use std::os::raw::c_char;
use crate::utils::tool_detection::detect_tool;
use crate::models::{TargetHost, Finding};
use anyhow::Result;
use std::panic::{catch_unwind, AssertUnwindSafe};
use once_cell::sync::Lazy;
use dashmap::DashSet;

/// V10 HARDENING: ABI Versioning to prevent memory corruption from incompatible plugins.
pub const PLUGIN_ABI_VERSION: u32 = 2;

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
    /// Returns the ABI version this plugin was compiled with.
    pub abi_version: extern "C" fn() -> u32,
    pub name: extern "C" fn(*const ()) -> *const c_char,
    /// Performs the scan. Returns a vector-like structure directly by value to avoid outer pointer leaks.
    pub scan: extern "C" fn(*const (), *const TargetHost) -> FFIFindings,
    pub plugin_ptr: *const (),
    pub destroy: extern "C" fn(*const ()),
}

unsafe impl Send for ScannerPluginFFI {}
unsafe impl Sync for ScannerPluginFFI {}

pub struct FFIPluginWrapper {
    pub ffi: ScannerPluginFFI,
    cached_name: &'static str,
    sync_lock: std::sync::Mutex<()>, // CRIT-FIX: Guarantee sequential FFI execution for unsafe plugins (HIGH-005)
}

static PLUGIN_NAME_CACHE: Lazy<DashSet<&'static str>> = Lazy::new(DashSet::new);

impl FFIPluginWrapper {
    pub fn new(ffi: ScannerPluginFFI) -> Result<Self> {
        // V10 ABI Handshake: Prevent loading incompatible plugins
        let version = (ffi.abi_version)();
        if version != PLUGIN_ABI_VERSION {
            anyhow::bail!("ABI MISMATCH: Plugin version {}, expected {}. Refusing to load to prevent memory corruption.", version, PLUGIN_ABI_VERSION);
        }

        let cached_name = unsafe {
            let c_str = (ffi.name)(ffi.plugin_ptr);
            if c_str.is_null() {
                "unknown"
            } else {
                let s = std::ffi::CStr::from_ptr(c_str).to_str().unwrap_or("unknown");
                if let Some(existing) = PLUGIN_NAME_CACHE.get(s) {
                    *existing
                } else {
                    let owned = s.to_string();
                    let leaked: &'static str = Box::leak(owned.into_boxed_str());
                    PLUGIN_NAME_CACHE.insert(leaked);
                    leaked
                }
            }
        };
        Ok(Self { ffi, cached_name, sync_lock: std::sync::Mutex::new(()) })
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
        Ok(crate::utils::check_tool_availability("ffi").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let _guard = self.sync_lock.lock().unwrap(); // Exclusive lock for thread-safety (HIGH-005)
        let ffi = &self.ffi;
        let plugin_ptr = ffi.plugin_ptr;
        let target_ptr = target as *const TargetHost;

        // PFC-001: Bridge de pánico para evitar que un bug en el plugin mate al orquestador
        let result = catch_unwind(AssertUnwindSafe(move || {
            unsafe { (ffi.scan)(plugin_ptr, target_ptr) }
        }));

        match result {
            Ok(ffi_findings) => {
                unsafe {
                    if ffi_findings.len > 1_000_000 {
                        anyhow::bail!("Security Violation: Plugin devolvió demasiados hallazgos ({}), abortando lectura para prevenir Heap Exhaustion.", ffi_findings.len);
                    }
                    
                    let cloned_findings = if ffi_findings.len > 0 {
                        if ffi_findings.data.is_null() {
                            anyhow::bail!("Security Violation: Plugin devolvió data null pero len > 0.");
                        }
                        let slice = std::slice::from_raw_parts(ffi_findings.data, ffi_findings.len);
                        slice.to_vec()
                    } else {
                        Vec::new()
                    };
                    
                    // Al terminar este bloque, `ffi_findings` se destruye y su impl Drop invoca a `free_fn` del plugin.
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

