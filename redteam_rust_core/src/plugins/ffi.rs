use std::sync::Mutex;
use std::os::raw::c_char;
use crate::models::{TargetHost, Finding};
use anyhow::Result;
use std::panic::{catch_unwind, AssertUnwindSafe};


/// V11 HARDENING: ABI Versioning to prevent memory corruption from incompatible plugins.
/// Incremented to 2 to reflect the addition of struct-level destructors for FFI.
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
    /// Function pointer to free the findings DATA (the slice)
    pub free_data_fn: extern "C" fn(*mut Finding, usize, usize),
}

/// A wrapper to ensure that dynamic plugins are FFI-safe.
#[repr(C)]
pub struct ScannerPluginFFI {
    /// Returns the ABI version this plugin was compiled with.
    pub abi_version: extern "C" fn() -> u32,
    pub name: extern "C" fn(*const ()) -> *const c_char,
    /// Performs the scan. Returns a raw pointer to a FFIFindings struct.
    pub scan: extern "C" fn(*const (), *const TargetHost) -> *mut FFIFindings,
    /// Destructor for the FFIFindings struct itself (to avoid allocator mismatch with Box::from_raw)
    pub free_findings_struct: extern "C" fn(*mut FFIFindings),
    pub plugin_ptr: *const (),
    pub destroy: extern "C" fn(*const ()),
}

unsafe impl Send for ScannerPluginFFI {}
unsafe impl Sync for ScannerPluginFFI {}

pub struct FFIPluginWrapper {
    pub ffi: ScannerPluginFFI,
    cached_name: &'static str,
    sync_lock: Mutex<()>,
}


impl FFIPluginWrapper {
    pub fn new(ffi: ScannerPluginFFI) -> Result<Self> {
        // V10 ABI Handshake: Prevent loading incompatible plugins
        let version = (ffi.abi_version)();
        if version != PLUGIN_ABI_VERSION {
            anyhow::bail!("ABI MISMATCH: Plugin version {}, expected {}. Refusing to load to prevent memory corruption.", version, PLUGIN_ABI_VERSION);
        }

        let name_str = unsafe {
            let c_str = (ffi.name)(ffi.plugin_ptr);
            if c_str.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(c_str).to_string_lossy().into_owned()
            }
        };
        // V12: satisfy &'static str requirement for dynamic plugins
        let cached_name = Box::leak(name_str.into_boxed_str());
        Ok(Self { ffi, cached_name, sync_lock: Mutex::new(()) })
    }
}

#[async_trait::async_trait]
impl crate::plugins::ScannerPlugin for FFIPluginWrapper {
    fn name(&self) -> &'static str {
        self.cached_name
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name().to_string(), 
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
        // V12 HARDENING: Serialize access to FFI scan method
        let _guard = self.sync_lock.lock().map_err(|_| anyhow::anyhow!("FFI Sync lock poisoned"))?;

        let ffi = &self.ffi;
        let plugin_ptr = ffi.plugin_ptr;
        let target_ptr = target as *const TargetHost;

        // PFC-001: Bridge de pánico para evitar que un bug en el plugin mate al orquestador
        let result = catch_unwind(AssertUnwindSafe(move || {
            (ffi.scan)(plugin_ptr, target_ptr)
        }));

        match result {
            Ok(findings_ptr) => {
                if findings_ptr.is_null() {
                    return Ok(Vec::new());
                }

                unsafe {
                    // V11 HARDENING (CRIT-002): Read the struct via pointer. 
                    // Do NOT use Box::from_raw to avoid allocator mismatch.
                    let ffi_findings = std::ptr::read(findings_ptr);
                    
                    // Validation of pointers and length before slice creation
                    if ffi_findings.data.is_null() && ffi_findings.len > 0 {
                         (ffi.free_findings_struct)(findings_ptr);
                         anyhow::bail!("Plugin '{}' returned null data pointer with non-zero length", self.cached_name);
                    }
                    
                    if ffi_findings.len > 100_000 { // Reasonable cap to prevent OOM
                         (ffi.free_findings_struct)(findings_ptr);
                         anyhow::bail!("Plugin '{}' returned suspiciously large number of findings ({})", self.cached_name, ffi_findings.len);
                    }

                    // 1. Read memory via FFI-safe slice (no ownership taken yet)
                    let slice = if ffi_findings.len > 0 {
                        std::slice::from_raw_parts(ffi_findings.data, ffi_findings.len)
                    } else {
                        &[]
                    };
                    
                    // 2. Clone to native Rust Vec (Host takes ownership of the clone)
                    let cloned_findings = slice.to_vec();
                    
                    // 3. Plugin-orchestrated cleanup:
                    // First, free the data inside the struct (allocated by the plugin)
                    (ffi_findings.free_data_fn)(ffi_findings.data, ffi_findings.len, ffi_findings.capacity);
                    
                    // Then, free the struct itself (allocated by the plugin)
                    (ffi.free_findings_struct)(findings_ptr);
                    
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
        (self.ffi.destroy)(self.ffi.plugin_ptr);
    }
}

