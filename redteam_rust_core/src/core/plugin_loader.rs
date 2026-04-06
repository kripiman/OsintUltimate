use crate::plugins::ScannerPlugin;
use crate::models::{TargetHost, Finding};
use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

use crate::plugins::ffi::{ScannerPluginFFI, FFIPluginWrapper};
use std::sync::Arc;

/// Signature for the external initialization function rust plugins must export.
/// Updated to return a FFI-safe struct.
type PluginCreateFunc = unsafe extern "C" fn() -> ScannerPluginFFI;

pub struct LoadedPlugin {
    pub plugin: Box<dyn ScannerPlugin>,
    _lib: Arc<Library>,
}

#[async_trait::async_trait]
impl ScannerPlugin for LoadedPlugin {
    fn name(&self) -> &'static str {
        self.plugin.name()
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        self.plugin.metadata()
    }

    fn capabilities(&self) -> Vec<crate::plugins::Capability> {
        self.plugin.capabilities()
    }

    async fn check_dependencies(&self) -> Result<bool> {
        self.plugin.check_dependencies().await
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        self.plugin.scan(target).await
    }
}

pub struct DynamicPluginLoader {
    // We no longer strictly need to hold libraries here if we use Arc<Library> in LoadedPlugin,
    // but keeping it for compatibility or as a secondary safety measure.
    loaded_libraries: Vec<Arc<Library>>,
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
                .context("Failed to find `_plugin_create` symbol in shared library. Make sure it exports `#[no_mangle] pub extern \"C\" fn _plugin_create() -> ScannerPluginFFI`")?;
            
            // Call the function to get the FFI-safe plugin struct
            let ffi_plugin = func();
            
            if ffi_plugin.plugin_ptr.is_null() {
                anyhow::bail!("Plugin creation function returned a null instance pointer");
            }

            let lib_arc = Arc::new(lib);
            self.loaded_libraries.push(lib_arc.clone());

            // PFC-002: El cargador ahora envuelve el plugin en LoadedPlugin que garantiza 
            // que la librería se mantenga cargada mientras el plugin exista (vía Arc).
            let wrapped_plugin = Box::new(LoadedPlugin {
                plugin: Box::new(FFIPluginWrapper::new(ffi_plugin)?),
                _lib: lib_arc,
            });
            
            Ok(wrapped_plugin)
        }
    }

    /// Verifies that the plugin was compiled with a compatible version of the core engine.
    /// AUDIT-002: Además de la versión, podríamos verificar un hash del ABI o features activas.
    fn verify_abi(lib: &Library) -> Result<()> {
        unsafe {
            let version_sym: Symbol<fn() -> &'static str> = lib.get(b"plugin_version\0")
                .context("Failed to find `plugin_version` symbol. Dynamic plugins must export this to ensure ABI compatibility.")?;
            
            let plugin_version = version_sym();
            let host_version = env!("CARGO_PKG_VERSION");

            if plugin_version != host_version {
                anyhow::bail!(
                    "Plugin ABI version mismatch! Plugin: {}, Host: {}. \
                    Plugins must be compiled against the exact same engine version to avoid memory corruption.",
                    plugin_version, host_version
                );
            }
            
            // TODO: Añadir verificación de 'magic number' o hash de estructuras críticas (TargetHost, Finding)
        }
        Ok(())
    }
}
