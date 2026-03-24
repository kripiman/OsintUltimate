use std::os::raw::c_char;
use crate::utils::tool_detection::detect_tool;
use crate::models::{TargetHost, Finding};
use anyhow::Result;

/// FFI-safe result for plugin names
#[repr(C)]
pub struct PluginNameFFI {
    pub name: *const c_char,
}

/// A wrapper to ensure that dynamic plugins are FFI-safe.
/// This is a simplified version of what a full ABI stable implementation would look like.
#[repr(C)]
pub struct ScannerPluginFFI {
    /// Returns the name of the plugin as a C string.
    pub name: extern "C" fn(*const ()) -> *const c_char,
    /// Performs the scan. This is a simplified synchronous version for FFI stability.
    /// In a real system, you'd use a more complex async bridge or stable-abi futures.
    pub scan: extern "C" fn(*const (), *const TargetHost) -> *mut Vec<Finding>,
    /// Opaque pointer to the actual plugin instance.
    pub plugin_ptr: *const (),
    /// Clean up the plugin instance.
    pub destroy: extern "C" fn(*const ()),
}

// SAFETY (QA-002): The plugin author MUST guarantee that:
// 1. `plugin_ptr` points to a thread-safe object (no unsynchronized mutable state).
// 2. All function pointers (`name`, `scan`, `destroy`) are safe to call from any thread.
// 3. The plugin was compiled against the exact same engine version (enforced by verify_abi()).
// Thread-safety violations are the plugin author's responsibility. Document this in the plugin SDK.
unsafe impl Send for ScannerPluginFFI {}
unsafe impl Sync for ScannerPluginFFI {}

/// A bridge between the FFI-safe interface and the internal `ScannerPlugin` trait.
/// QA-001 FIX: Caches the plugin name at construction time to avoid repeated Box::leak() calls.
pub struct FFIPluginWrapper {
    pub ffi: ScannerPluginFFI,
    cached_name: &'static str,
}

impl FFIPluginWrapper {
    /// Constructs the wrapper, calling the FFI name function once and caching the result.
    /// The single Box::leak() call here is acceptable because plugins live for the entire process.
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
        // QA-001 FIX: Return cached name instead of leaking memory on every call.
        self.cached_name
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name(),
            description: "Dynamic plugin loaded via FFI.",
            target_type: crate::plugins::TargetType::Host, // Default for FFI
            risk_level: crate::plugins::RiskLevel::Medium,
            layer: crate::core::capability_layer::ScanLayer::Scanning,
            expected_duration: std::time::Duration::from_secs(300),
            capabilities: self.capabilities(),
            cost: 5,
            category: "General",
            mitre_attacks: vec![],
            remediation_difficulty: crate::plugins::RiskLevel::Medium,
        }
    }
    fn capabilities(&self) -> Vec<crate::plugins::Capability> {
        vec![crate::plugins::Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(crate::utils::check_tool_availability("ffi").await)
    }


    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        unsafe {
            let findings_ptr = (self.ffi.scan)(self.ffi.plugin_ptr, target);
            if findings_ptr.is_null() {
                return Ok(Vec::new());
            }
            let findings = *Box::from_raw(findings_ptr);
            Ok(findings)
        }
    }
}

impl Drop for FFIPluginWrapper {
    fn drop(&mut self) {
        (self.ffi.destroy)(self.ffi.plugin_ptr);
    }
}
