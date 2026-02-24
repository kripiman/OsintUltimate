use crate::plugins::ScannerPlugin;
use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

/// Signature for the external initialization function rust plugins must export.
/// Since there is no stable Rust ABI, the plugin MUST be compiled with the same rustc version
/// and core dependencies as the host binary.
type PluginCreateFunc = unsafe extern "C" fn() -> *mut dyn ScannerPlugin;

pub struct DynamicPluginLoader {
    // We hold onto the Library instances because dropping them unloads the code,
    // which would cause a segfault if the loaded plugins are still executing.
    loaded_libraries: Vec<Library>,
}

impl DynamicPluginLoader {
    pub fn new() -> Self {
        Self {
            loaded_libraries: Vec::new(),
        }
    }

    /// Recursively scans a directory for `.so` (Linux) or `.dylib` (macOS) files
    /// and attempts to load them as `ScannerPlugin` trait objects.
    pub fn load_plugins_from_dir(&mut self, dir_path: &Path) -> Result<Vec<Box<dyn ScannerPlugin>>> {
        let mut loaded_plugins = Vec::new();

        if !dir_path.exists() || !dir_path.is_dir() {
            warn!("Plugin directory {:?} does not exist or is not a directory.", dir_path);
            return Ok(loaded_plugins);
        }

        info!("Scanning for dynamic plugins in {:?}", dir_path);

        for entry in fs::read_dir(dir_path).context("Failed to read plugin directory")? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy();
                    if ext_str == "so" || ext_str == "dylib" {
                        match self.load_plugin(&path) {
                            Ok(plugin) => {
                                info!("🔌 Successfully loaded dynamic plugin: {}", plugin.name());
                                loaded_plugins.push(plugin);
                            }
                            Err(e) => {
                                error!("Failed to load plugin from {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        }

        Ok(loaded_plugins)
    }

    /// Loads a single shared library and extracts the `_plugin_create` symbol.
    fn load_plugin(&mut self, path: &Path) -> Result<Box<dyn ScannerPlugin>> {
        unsafe {
            // Load the shared library
            let lib = Library::new(path).with_context(|| format!("Failed to load library {:?}", path))?;

            // AUDIT-001 FIX: Verify ABI/Version compatibility before instantiation
            Self::verify_abi(&lib)?;
            
            // Locate the exported initialization function
            let func: Symbol<PluginCreateFunc> = lib.get(b"_plugin_create\0")
                .context("Failed to find `_plugin_create` symbol in shared library. Make sure it exports `#[no_mangle] pub extern \"C\" fn _plugin_create() -> *mut dyn ScannerPlugin`")?;
            
            // Call the function to get the raw pointer, then convert it to a Box
            let raw_plugin_ptr = func();
            
            if raw_plugin_ptr.is_null() {
                anyhow::bail!("Plugin creation function returned a null pointer");
            }

            let plugin = Box::from_raw(raw_plugin_ptr);
            
            // Retain the library in memory so it doesn't get unloaded while the plugin is alive
            self.loaded_libraries.push(lib);
            
            Ok(plugin)
        }
    }

    /// Verifies that the plugin was compiled with a compatible version of the core engine.
    /// Rust lacks a stable ABI, so mismatching versions or dependencies can cause memory corruption.
    fn verify_abi(lib: &Library) -> Result<()> {
        unsafe {
            let version_sym: Symbol<fn() -> &'static str> = lib.get(b"plugin_version\0")
                .context("Failed to find `plugin_version` symbol. Dynamic plugins must export this to ensure ABI compatibility.")?;
            
            let plugin_version = version_sym();
            let host_version = env!("CARGO_PKG_VERSION");

            if plugin_version != host_version {
                anyhow::bail!(
                    "Plugin ABI version mismatch! Plugin: {}, Host: {}. \
                    Plugins must be compiled against the exact same engine version.",
                    plugin_version, host_version
                );
            }
        }
        Ok(())
    }
}
