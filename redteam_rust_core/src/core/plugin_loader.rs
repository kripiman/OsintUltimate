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

impl Default for DynamicPluginLoader {
    fn default() -> Self {
        Self::new()
    }
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
                    } else if ext_str == "wasm" {
                        match self.load_wasm_plugin(&path) {
                            Ok(plugin) => {
                                info!("🦀 Successfully loaded WASM plugin: {}", plugin.name());
                                loaded_plugins.push(plugin);
                            }
                            Err(e) => {
                                error!("Failed to load WASM plugin from {:?}: {}", path, e);
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
        // FIX DE AISLAMIENTO: Verificar rutas permitidas y seguras (MED-001 canonicalize)
        let canonical_path = std::fs::canonicalize(path).with_context(|| format!("Failed to canonicalize path: {:?}", path))?;
        let temp_dir = std::env::temp_dir();
        if canonical_path.starts_with(&temp_dir) {
            anyhow::bail!("Security Violation: Carga de plugin dinámico rechazada desde directorio temporal: {:?}", canonical_path);
        }

        let path_str = canonical_path.to_string_lossy();
        if path_str.contains("..") {
             anyhow::bail!("Security Violation: Carga de plugin dinámico rechazada. Ruta peligrosa: {:?}", canonical_path);
        }

        // V12 HARDENING: Acquire lock/handle BEFORE reading bytes for verification.
        #[cfg(unix)]
        let (mut _file, fd) = {
            let f = std::fs::File::open(&canonical_path).context("Failed to open plugin for FD loading")?;
            use std::os::unix::io::AsRawFd;
            let fd = f.as_raw_fd();
            (f, fd)
        };

        #[cfg(windows)]
        let mut _lock = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1) // FILE_SHARE_READ only: Prevents write/delete by others
                .open(&canonical_path)
                .context("V12: Failed to acquire exclusive read lock on Windows plugin")?
        };

        // V13 HARDENING: Signature & Integrity verification WHILE HOLDING THE LOCK.
        // F2-002 FIX: Read directly from the locked file descriptor, NOT the canonical path to prevent TOCTOU.
        let mut plugin_bytes = Vec::new();
        use std::io::Read;
        #[cfg(unix)]
        _file.read_to_end(&mut plugin_bytes)
            .with_context(|| format!("V13 Violation: Failed to read plugin bytes from locked FD at {:?}", canonical_path))?;
            
        #[cfg(windows)]
        _lock.read_to_end(&mut plugin_bytes)
            .with_context(|| format!("V13 Violation: Failed to read plugin bytes from locked handle at {:?}", canonical_path))?;

        Self::verify_signature_from_bytes(&canonical_path, &plugin_bytes)?;

        let lib = {
            #[cfg(unix)]
            {
                unsafe { Library::new(format!("/proc/self/fd/{}", fd)).with_context(|| format!("Failed to load FD library {:?}", canonical_path))? }
            }
            #[cfg(windows)]
            {
                unsafe { Library::new(&canonical_path).with_context(|| format!("Failed to load Windows library {:?}", canonical_path))? }
            }
            #[cfg(not(any(unix, windows)))]
            {
                unsafe { Library::new(&canonical_path).with_context(|| format!("Failed to load library {:?}", canonical_path))? }
            }
        };

        // Ensure _lock or file (Unix) is kept alive until loading is complete.
        // On Unix, the FD loading is already atomic because it uses the FD.
        // On Windows, the _lock handle prevents modification while Library::new runs.

        unsafe {

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
            let version_sym: Symbol<unsafe extern "C" fn() -> *const std::os::raw::c_char> = lib.get(b"plugin_version\0")
                .context("Failed to find `plugin_version` symbol. Dynamic plugins must export this to ensure ABI compatibility.")?;
            
            let plugin_version_ptr = version_sym();
            if plugin_version_ptr.is_null() {
                anyhow::bail!("plugin_version returned null pointer");
            }
            let plugin_version = std::ffi::CStr::from_ptr(plugin_version_ptr).to_string_lossy();
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

    /// Extracs Ed25519 public key and verifies plugin integrity against its `.sig` file.
    fn verify_signature_from_bytes(path: &Path, plugin_bytes: &[u8]) -> Result<()> {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        use std::fs;
        
        // V13 CRITICAL: Mandatory environment check. No fallback allowed.
        let public_key_hex = std::env::var("OSINT_PLUGIN_PUBKEY")
            .map_err(|_| {
                error!("🛑 SECURITY ERROR: OSINT_PLUGIN_PUBKEY environment variable is NOT SET.");
                anyhow::anyhow!("V13 Security Violation: Mandatory plugin verification key missing. Refusing to load unsigned/unverified plugins.")
            })?;
        
        if public_key_hex.trim().is_empty() {
            anyhow::bail!("V13 Security Violation: OSINT_PLUGIN_PUBKEY is empty. A valid Ed25519 public key is required.");
        }

        let pk_bytes = hex::decode(public_key_hex.trim()).context("Invalid public key hex in OSINT_PLUGIN_PUBKEY")?;
        let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| anyhow::anyhow!("Public Key length mismatch (Expected 32 bytes)"))?;
        let public_key = VerifyingKey::from_bytes(&pk_array).context("Invalid Ed25519 public key format")?;

        let sig_path = std::path::PathBuf::from(format!("{}.sig", path.display()));
        if !sig_path.exists() {
            anyhow::bail!("Security Violation: No cryptographic signature (.sig) found for plugin at {:?}", path);
        }

        let sig_hex = fs::read_to_string(&sig_path).context("Failed to read plugin signature file")?;
        let sig_bytes = hex::decode(sig_hex.trim()).context("Invalid signature hex format")?;
        let signature = Signature::from_slice(&sig_bytes).context("Invalid signature length")?;

        public_key.verify(plugin_bytes, &signature)
            .map_err(|e| {
                error!("🛑 UNTRUSTED PLUGIN DETECTED: Signature verification FAILED for {:?}. Possible tampering or MITM.", path);
                anyhow::anyhow!("V13 Plugin Integrity Failure: {}", e)
            })?;
            
        Ok(())
    }

    fn load_wasm_plugin(&self, path: &Path) -> Result<Box<dyn ScannerPlugin>> {
        let bytes = std::fs::read(path).context("Failed to read WASM plugin")?;
        
        // V13 Signature Verification (WASM plugins also need .sig)
        Self::verify_signature_from_bytes(path, &bytes)?;

        Ok(Box::new(WasmPlugin {
            name: path.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
            bytes,
            rt: crate::core::sandbox::wasm::WasmRuntime::new(),
        }))
    }
}

pub struct WasmPlugin {
    name: String,
    bytes: Vec<u8>,
    rt: crate::core::sandbox::wasm::WasmRuntime,
}

#[async_trait::async_trait]
impl ScannerPlugin for WasmPlugin {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn metadata(&self) -> crate::plugins::PluginMetadata {
        crate::plugins::PluginMetadata {
            name: self.name.clone(),
            description: "WASM Sandboxed Plugin".to_string(),
            ..Default::default()
        }
    }

    fn capabilities(&self) -> Vec<crate::plugins::Capability> {
        vec![crate::plugins::Capability::VulnerabilityScanning]
    }

    async fn check_dependencies(&self) -> Result<bool> {
        Ok(true)
    }

    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        let input = serde_json::to_string(target)?;
        let output = self.rt.execute_plugin(&self.bytes, &input)?;
        let findings = serde_json::from_str(&output)?;
        Ok(findings)
    }
}
