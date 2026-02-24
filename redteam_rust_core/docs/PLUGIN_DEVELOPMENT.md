# 🔌 Guía de Desarrollo de Plugins

OsintUltimate aprovecha una arquitectura modular donde cada capacidad de escaneo es un plugin que implementa el trait `ScannerPlugin`.

## El Trait Interface

Ubicado en `src/plugins/mod.rs`:

```rust
#[async_trait]
pub trait ScannerPlugin: Send + Sync {
    /// Identificador único para el plugin (ej., "WebFuzzer")
    fn name(&self) -> &'static str;
    
    /// La lógica central. Modifica el target_host in-place.
    async fn scan(&self, target: &mut TargetHost) -> Result<()>;
}
```

## Creando un Nuevo Scanner

### Paso 1: Definir la Estructura
Tu struct puede contener configuraciones (ej., puertos, listas de palabras).

```rust
pub struct MyCustomScanner {
    port: u16,
}
```

### Paso 2: Implementar el Trait

```rust
use async_trait::async_trait;
use crate::models::{TargetHost, Finding, Severity, Category};
use crate::plugins::ScannerPlugin;
use anyhow::Result;

#[async_trait]
impl ScannerPlugin for MyCustomScanner {
    fn name(&self) -> &'static str {
        "MyCustomScanner"
    }

    async fn scan(&self, target: &mut TargetHost) -> Result<()> {
        // 1. Realizar la lógica (ej., solicitud de red)
        // Usar tokio::net::TcpStream o reqwest
        
        // 2. Añadir hallazgos (Findings) si es vulnerable
        if es_vulnerable {
             target.findings.push(Finding::new(
                "VULN-ID-001",
                Category::Network,
                Severity::High,
                "Puerto Abierto Detectado",
                serde_json::json!({ "port": self.port })
            ));
        }
        
        Ok(())
    }
}
```

### Paso 3: Registrar en `main.rs`

```rust
// En main.rs
orchestrator.register_plugin(Box::new(MyCustomScanner { port: 8080 })).await;
```

## Mejores Prácticas

1.  **No Bloqueante**: Nunca uses `std::thread::sleep` o E/S bloqueante. Usa `tokio`.
2.  **Manejo de Errores**: Devuelve `Ok(())` incluso si el escaneo "no encontró nada". Solo devuelve `Err` si el plugin en sí falló (ej., error de configuración).
3.  **Concurrencia**: El orquestador maneja el paralelismo. Tu instancia de plugin se comparte (`Arc<RwLock<...>>`), por lo que `&self` es inmutable.

## Plugins Dinámicos (Librerías Compartidas `.so` / `.dylib`)

Puedes compilar plugins como librerías dinámicas independientes. El núcleo verifica la compatibilidad de la **ABI** y el **Versionado** antes de cargar cualquier plugin por seguridad. Pasa `--plugins-dir <ruta>` al ejecutar OsintUltimate para cargarlos.

### Paso 1: Configurar el `Cargo.toml` externo
Asegúrate de configurar el tipo de crate como `cdylib` e importa las dependencias núcleo (como redteam_rust_core y anyhow).
```toml
[lib]
crate-type = ["cdylib"]
```

### Paso 2: Exportar la Instancia y Versión
En el archivo `lib.rs` de tu plugin externo, debes exportar la función `_plugin_create` y `plugin_version`. **Importante**: Debido a que Rust no tiene una ABI estable, el plugin DEBE exportar estos símbolos con `extern "C"`.

```rust
use redteam_rust_core::plugins::ScannerPlugin;
use redteam_rust_core::models::TargetHost;
use anyhow::Result;
use async_trait::async_trait;

pub struct ExternalPlugin;

#[async_trait]
impl ScannerPlugin for ExternalPlugin {
    fn name(&self) -> &'static str { "ExternalScannerDynamic" }
    async fn scan(&self, target: &TargetHost) -> Result<Vec<Finding>> {
        // Lógica de escaneo (ahora recibe &TargetHost por optimización Arc)
        Ok(vec![])
    }
}

// Exportar la versión para validación ABI
#[no_mangle]
pub extern "C" fn plugin_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[no_mangle]
pub extern "C" fn _plugin_create() -> *mut dyn ScannerPlugin {
    let plugin = Box::new(ExternalPlugin);
    Box::into_raw(plugin)
}
```

### Paso 3: Ejecución
Pasa la ruta durante el inicio:
```bash
cargo run --release -- --target example.com --plugins-dir ./external_plugins/target/release/
```
