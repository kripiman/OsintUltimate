use std::os::raw::c_char;
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

unsafe impl Send for ScannerPluginFFI {}
unsafe impl Sync for ScannerPluginFFI {}

/// A bridge between the FFI-safe interface and the internal `ScannerPlugin` trait.
pub struct FFIPluginWrapper {
    pub ffi: ScannerPluginFFI,
}

#[async_trait::async_trait]
impl crate::plugins::ScannerPlugin for FFIPluginWrapper {
    fn name(&self) -> &'static str {
        unsafe {
            let c_str = (self.ffi.name)(self.ffi.plugin_ptr);
            if c_str.is_null() {
                return "unknown";
            }
            let s = std::ffi::CStr::from_ptr(c_str).to_str().unwrap_or("unknown");
            // Leak the string to satisfy 'static lifetime. 
            // In a real plugin system, we'd have a better ownership model.
            Box::leak(s.to_string().into_boxed_str())
        }
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
        unsafe {
            (self.ffi.destroy)(self.ffi.plugin_ptr);
        }
    }
}
