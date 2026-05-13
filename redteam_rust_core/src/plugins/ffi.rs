use tokio::sync::Mutex;
use std::os::raw::c_char;
use crate::models::{TargetHost, Finding};
use anyhow::Result;
use std::panic::{catch_unwind, AssertUnwindSafe};


/// V11 HARDENING: ABI Versioning to prevent memory corruption from incompatible plugins.
/// Incremented to 3 to reflect the transition to full #[repr(C)] models (FindingFFI/TargetHostFFI).
pub const PLUGIN_ABI_VERSION: u32 = 3;

// FFI Contract Constants for Category
pub const CATEGORY_EXPOSED_ASSET:    u8 = 0;
pub const CATEGORY_VULNERABILITY:    u8 = 1;
pub const CATEGORY_MISCONFIGURATION: u8 = 2;
pub const CATEGORY_CREDENTIAL_LEAK:  u8 = 3;
pub const CATEGORY_TECHNOLOGY_STACK: u8 = 4;
pub const CATEGORY_NETWORK_PORT:     u8 = 5;
pub const CATEGORY_RECON:            u8 = 6;
pub const CATEGORY_SCANNING:         u8 = 7;
pub const CATEGORY_AVAILABILITY:     u8 = 8;
pub const CATEGORY_SCA:              u8 = 9;
pub const CATEGORY_POSTURE_AUDIT:    u8 = 10;
pub const CATEGORY_WINDOWS:          u8 = 11;
pub const CATEGORY_LINUX:            u8 = 12;

// FFI Contract Constants for Severity
pub const SEVERITY_INFO:     u8 = 0;
pub const SEVERITY_LOW:      u8 = 1;
pub const SEVERITY_MEDIUM:   u8 = 2;
pub const SEVERITY_HIGH:     u8 = 3;
pub const SEVERITY_CRITICAL: u8 = 4;

/// FFI-safe result for plugin names
#[repr(C)]
pub struct PluginNameFFI {
    pub name: *const c_char,
}

/// V15 HARDENING: FFI-safe representation of TargetHost.
/// Using only primitive types to ensure stable ABI across Rust/C boundaries.
#[repr(C)]
pub struct TargetHostFFI {
    pub host: *const c_char,
    pub ip: *const c_char,
    pub status: u8,
    pub target_type: u8,
}

/// V15 HARDENING: FFI-safe representation of a Finding.
/// 
/// /// SAFETY CONTRACT: All *const c_char pointers in this struct are owned by the plugin.
/// The plugin's free_data_fn is responsible for freeing both the strings and the struct.
/// The host MUST NOT call free() on any pointer in this struct directly.
#[repr(C)]
pub struct FindingFFI {
    pub category: u8,
    pub severity: u8,
    pub title: *const c_char,
    pub description: *const c_char,
    pub evidence_json: *const c_char, // Serialized JSON for complex data
}

/// FFI-safe wrapper for a vector of findings.
/// This avoids allocator mismatch issues by providing a dedicated destructor.
#[repr(C)]
pub struct FFIFindings {
    pub data: *mut FindingFFI,
    pub len: usize,
    pub capacity: usize,
    /// Function pointer to free the findings DATA (the slice of FindingFFI)
    /// The plugin implementation MUST also free internal strings within each FindingFFI.
    pub free_data_fn: extern "C" fn(*mut FindingFFI, usize, usize),
}

/// A wrapper to ensure that dynamic plugins are FFI-safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScannerPluginFFI {
    /// Returns the ABI version this plugin was compiled with.
    pub abi_version: extern "C" fn() -> u32,
    /// Returns the expected duration of the scan in seconds (used for Host-side timeouts).
    pub expected_duration: extern "C" fn() -> u64,
    pub name: extern "C" fn(*const ()) -> *const c_char,
    /// Performs the scan. Returns a raw pointer to a FFIFindings struct.
    pub scan: extern "C" fn(*const (), *const TargetHostFFI) -> *mut FFIFindings,
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
        let expected_secs = (self.ffi.expected_duration)();
        crate::plugins::PluginMetadata {
            name: self.name().to_string(), 
            description: "Dynamic plugin loaded via SafeFFI bridge.".to_string(),
            target_type: crate::plugins::TargetType::Host,
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(expected_secs),
            capabilities: self.capabilities(),
            cost: 5,
            category: "General".to_string(),
            mitre_attacks: vec![],
            exploit_difficulty: crate::plugins::RiskLevel::Medium,
            blackarch_category: None,
            is_destructive: false,
            poc_mode: true, ..Default::default() }
    }

    fn capabilities(&self) -> Vec<crate::plugins::Capability> {
        vec![crate::plugins::Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ffi").await)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // V12 HARDENING: Serialize access to FFI scan method
        let _guard = self.sync_lock.lock().await;

        let ffi = self.ffi;
        let plugin_ptr = ffi.plugin_ptr;
        let plugin_ptr_usize = plugin_ptr as usize;
        
        // V15 HARDENING: Map native TargetHost to FFI-safe TargetHostFFI
        use std::ffi::CString;
        let c_host = CString::new(target.host.as_str()).unwrap_or_default();
        let c_ip = CString::new(target.target_addr()).unwrap_or_default();
        let target_status = target.status.clone() as u8;
        let target_type = target.target_type as u8;

        let timeout_duration = self.metadata().expected_duration;

        // V15 HARDENING: Wrap raw pointer to make it Send for transport between threads.
        struct SendPtr(*mut FFIFindings);
        unsafe impl Send for SendPtr {}

        // PFC-001: Bridge de pánico + spawn_blocking + timeout
        let result = tokio::time::timeout(timeout_duration, tokio::task::spawn_blocking(move || {
            let inner_plugin_ptr = plugin_ptr_usize as *const ();

            // SAFETY: CStrings are moved into this closure and kept alive explicitly
            // until the scan returns, preventing potential Use-After-Free in the plugin.
            let target_ffi = TargetHostFFI {
                host: c_host.as_ptr(),
                ip: c_ip.as_ptr(),
                status: target_status,
                target_type,
            };

            let result = catch_unwind(AssertUnwindSafe(move || {
                (ffi.scan)(inner_plugin_ptr, &target_ffi as *const TargetHostFFI)
            }));
            
            // Explicitly drop CStrings AFTER ffi.scan returns
            drop(c_host);
            drop(c_ip);
            
            result.map(SendPtr)
        })).await;

        let findings_ptr = match result {
            Ok(Ok(Ok(send_ptr))) => send_ptr.0,
            Ok(Ok(Err(_))) => anyhow::bail!("Plugin '{}' panicked during scan execution", self.cached_name),
            Ok(Err(e)) => anyhow::bail!("Plugin execution task failed: {}", e),
            Err(_) => anyhow::bail!("Plugin '{}' timed out after {:?}", self.cached_name, timeout_duration),
        };

        if findings_ptr.is_null() {
            return Ok(Vec::new());
        }

        unsafe {
            use std::ffi::CStr;
            // V11 HARDENING (CRIT-002): Read the struct via pointer. 
            let ffi_findings = std::ptr::read(findings_ptr);
            
            // Validation of pointers and length before slice creation
            if ffi_findings.data.is_null() && ffi_findings.len > 0 {
                    (ffi.free_findings_struct)(findings_ptr);
                    anyhow::bail!("Plugin '{}' returned null data pointer with non-zero length", self.cached_name);
            }
            
            if ffi_findings.len > 10_000 { // Reduced cap for safety
                    (ffi.free_findings_struct)(findings_ptr);
                    anyhow::bail!("Plugin '{}' returned suspiciously large number of findings ({})", self.cached_name, ffi_findings.len);
            }

            // 1. Read memory via FFI-safe slice (FindingFFI layout is stable)
            let slice = if ffi_findings.len > 0 {
                std::slice::from_raw_parts(ffi_findings.data, ffi_findings.len)
            } else {
                &[]
            };
            
            // 2. Map FindingFFI back to native Findings
            let mut native_findings = Vec::with_capacity(ffi_findings.len);
            for f_ffi in slice {
                let title = CStr::from_ptr(f_ffi.title).to_string_lossy().into_owned();
                let desc = CStr::from_ptr(f_ffi.description).to_string_lossy().into_owned();
                let evidence_raw = CStr::from_ptr(f_ffi.evidence_json).to_string_lossy();
                let evidence: serde_json::Value = serde_json::from_str(&evidence_raw).unwrap_or(serde_json::json!({}));
                
                let severity = severity_from_u8(f_ffi.severity);
                let category = category_from_u8(f_ffi.category);

                let mut finding = Finding::new(&uuid::Uuid::new_v4().to_string(), category, severity, &desc, evidence);
                finding.core.title = title;
                native_findings.push(finding);
            }
            
            // 3. Plugin-orchestrated cleanup:
            // SAFETY: As per contract, free_data_fn must free strings and the data array.
            (ffi_findings.free_data_fn)(ffi_findings.data, ffi_findings.len, ffi_findings.capacity);
            (ffi.free_findings_struct)(findings_ptr);
            
            Ok(native_findings)
        }
    }
}

// Helper conversion functions for Enum Mapping

pub(crate) fn category_from_u8(v: u8) -> crate::models::Category {
    use crate::models::Category::*;
    match v {
        CATEGORY_EXPOSED_ASSET    => ExposedAsset,
        CATEGORY_VULNERABILITY    => Vulnerability,
        CATEGORY_MISCONFIGURATION => Misconfiguration,
        CATEGORY_CREDENTIAL_LEAK  => CredentialLeak,
        CATEGORY_TECHNOLOGY_STACK => TechnologyStack,
        CATEGORY_NETWORK_PORT     => NetworkPort,
        CATEGORY_RECON           => Recon,
        CATEGORY_SCANNING        => Scanning,
        CATEGORY_AVAILABILITY    => Availability,
        CATEGORY_SCA             => SCA,
        CATEGORY_POSTURE_AUDIT    => PostureAudit,
        CATEGORY_WINDOWS         => Windows,
        CATEGORY_LINUX           => Linux,
        _  => Scanning, // Fallback documentado
    }
}

pub(crate) fn severity_from_u8(v: u8) -> crate::models::Severity {
    use crate::models::Severity::*;
    match v {
        SEVERITY_LOW      => Low,
        SEVERITY_MEDIUM   => Medium,
        SEVERITY_HIGH     => High,
        SEVERITY_CRITICAL => Critical,
        _ => Info, // Fallback a Info
    }
}

impl Drop for FFIPluginWrapper {
    fn drop(&mut self) {
        (self.ffi.destroy)(self.ffi.plugin_ptr);
    }
}

