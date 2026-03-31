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

## 🎯 Integración con BlackArch (Sistema de Herramientas)

A partir de v4.0, OsintUltimate detecta automáticamente herramientas de BlackArch instaladas en el sistema y las utiliza en lugar de binarios embebidos. Esto proporciona:

- **Eficiencia**: Reutiliza binarios del sistema en lugar de embeddings
- **Compatibilidad**: Soporte automático para distribuciones especializadas (BlackArch, Kali, Parrot)
- **Fallback seguro**: Usa binarios embebidos si no se encuentra la herramienta

### Sistema de Detección Automática

La detección de herramientas se realiza mediante el módulo `utils::tool_detection`:

```rust
use crate::utils::tool_detection::{detect_tool, check_tool_availability, verify_tool_version};

// 1. Detección simple
let ffuf_path = detect_tool("ffuf"); // Returns String (path or tool name as fallback)

// 2. Verificación asíncrona de disponibilidad
if check_tool_availability("nuclei").await {
    println!("nuclei está disponible y es ejecutable");
}

// 3. Validación de versión (opcional)
if verify_tool_version("sqlmap", Some("1.5")).await? {
    println!("sqlmap meet minimum version requirement");
}
```

### Herramientas Soportadas Actualmente

| Herramienta | Plugin | Módulo | Estado |
|-------------|--------|--------|--------|
| ffuf | FfufScanner | enumeration/web | ✅ Integrado |
| nuclei | NucleiScanner | intelligence | ✅ Integrado |
| sqlmap | SqlMapScanner | exploitation/web | ✅ Integrado |
| rustscan | RustScanScanner | enumeration/network | ✅ Integrado |
| arjun | ArjunScanner | enumeration/web | ✅ Integrado |
| jaeles | JaelesScanner | intelligence | ✅ Integrado |
| kubescape | KubescapeScanner | compliance | ✅ Integrado |
| searchsploit | SearchsploitScanner | intelligence | ✅ Integrado |
| certipy | CertipyScanner | privilege_escalation | ✅ Integrado |
| netexec | NetExecScanner | exploitation/network | ✅ Integrado |
| coercer | CoercerScanner | exploitation/network | ✅ Integrado |
| dalfox | DalfoxScanner | exploitation/web | ✅ Integrado |
| graphql_cop | GraphQLCopScanner | exploitation/web | ✅ Integrado |
| wapiti | WapitiScanner | exploitation/web | ✅ Integrado |
| jwt_tool | JWTToolScanner | exploitation/web | ✅ Integrado |
| hydra | HydraScanner | exploitation/network | ✅ Integrado |
| responder | ResponderScanner | exploitation/network | ✅ Integrado |
| petitpotam | PetitPotamScanner | exploitation/network | ✅ Integrado |
| bloodhound | BloodHoundScanner | lateral_movement | ✅ Integrado |
| ligolo | LigoloScanner | lateral_movement | ✅ Integrado |
| sliver | SliverScanner | lateral_movement | ✅ Integrado |
| havoc | HavocScanner | persistence | ✅ Integrado |
| dnsx | DNSXScanner | reconnaissance/active | ✅ Integrado |
| httpx | HTTPXScanner | reconnaissance/active | ✅ Integrado |
| naabu | NaabuScanner | reconnaissance/active | ✅ Integrado |
| wayback | WaybackScanner | reconnaissance/passive | ✅ Integrado |
| uncover | UncoverScanner | reconnaissance/osint | ✅ Integrado |
| gauplus | GauPlusScanner | enumeration/web | ✅ Integrado |
| interactsh | InteractshScanner | enumeration/web | ✅ Integrado |
| feroxbuster | FeroxbusterScanner | enumeration/web | ✅ Integrado |
| gowitness | GoWitnessScanner | enumeration/web | ✅ Integrado |
| cloudenum | CloudEnumScanner | enumeration/cloud | ✅ Integrado |
| cloudbrute | CloudBruteScanner | enumeration/cloud | ✅ Integrado |
| cloudfox | CloudFoxScanner | enumeration/cloud | ✅ Integrado |
| pacu | PacuScanner | enumeration/cloud | ✅ Integrado |
| trivy | TrivyScanner | compliance | ✅ Integrado |

**Total integrado: 35+ plugins** | **Estado: ✅ BlackArch Ready**

## 🚀 Plugins Nativos (io-uring) - NUEVO en v4.0

Para tareas de red que requieren una latencia extremadamente baja (como port scanning masivo), OsintUltimate v4.0 introduce el trait `NativeScanner`. Estos plugins operan mediante `io-uring` para bypassar el modelo tradicional de subprocesos.

### Implementación del Trait NativeScanner
Ubicado en `src/core/native_scanner.rs`.

```rust
pub trait NativeScanner: Send + Sync {
    fn name(&self) -> &str;
    async fn scan(&self, target: &str) -> Result<Vec<crate::models::Finding>>;
}
```

### Ventajas del Modelo Nativo:
1. **Zero-Copy**: Envío de paquetes directamente desde buffers compartidos con el kernel.
2. **Lock-Free**: Ingestión de resultados directamente en el `LockFreeResultSink`.
3. **Escala**: Capaz de manejar >100k paquetes por segundo sin saturar el planificador de hilos de Rust.

---

### Instalación de Herramientas (para pruebas)

En BlackArch o Kali:
```bash
# Instalar herramientas individuales
sudo pacman -S ffuf nuclei sqlmap rustscan

# O instalar la suite de categoría
sudo pacman -S blackarch-webapp
```

En Debian/Ubuntu:
```bash
# FFuf
sudo apt-get install ffuf

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# SQLMap
sudo apt-get install sqlmap

# RustScan
cargo install rustscan
```
