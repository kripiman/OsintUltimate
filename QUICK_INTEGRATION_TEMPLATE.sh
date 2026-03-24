#!/bin/bash
# 📋 Template Rápido: Integrar Nueva Herramienta BlackArch en OsintUltimate

# Este script muestra cómo agregar rápidamente soporte de detección
# para una nueva herramienta del sistema en un plugin existente.

# ============================================================================
# PASO 1: Identificar el Plugin a Actualizar
# ============================================================================

PLUGIN_FILE="src/plugins/enumeration/web/arjun.rs"  # Por ejemplo
TOOL_NAME="arjun"

echo "📝 Actualizando $PLUGIN_FILE para detectar $TOOL_NAME del sistema..."

# ============================================================================
# PASO 2: Cambio - Agregar Import
# ============================================================================

# ANTES:
# use crate::plugins::{ScannerPlugin, Capability};
# use async_trait::async_trait;

# DESPUÉS:
# use crate::plugins::{ScannerPlugin, Capability};
# use crate::utils::tool_detection::detect_tool;  ← AGREGAR ESTA LÍNEA
# use async_trait::async_trait;

cat << 'EOF'

✏️  CAMBIOS NECESARIOS:

1. En la sección de IMPORTS:
   add: use crate::utils::tool_detection::detect_tool;

2. En la función new():
   ANTES:  let path = which::which("arjun").unwrap_or_else(|_| "arjun".into());
   DESPUÉS: let path = detect_tool("arjun");

3. En la sección de binary_path assignment:
   ANTES:  binary_path: path.to_string_lossy().to_string(),
   DESPUÉS: binary_path: path,

4. En check_dependencies():
   ANTES:  Ok(which::which("arjun").is_ok())
   DESPUÉS: Ok(crate::utils::check_tool_availability("arjun").await)

EOF

# ============================================================================
# PASO 3: Validación (Pseudocódigo)
# ============================================================================

echo "
✅ VALIDACIÓN:

# Verificar que el import está presente
grep 'use crate::utils::tool_detection::detect_tool' $PLUGIN_FILE

# Verificar que se usa en new()
grep 'detect_tool(\"$TOOL_NAME\")' $PLUGIN_FILE

# Verificar que check_dependencies fue actualizado
grep 'check_tool_availability(\"$TOOL_NAME\")' $PLUGIN_FILE
"

# ============================================================================
# PASO 4: Compilar y Probar
# ============================================================================

echo "
🧪 COMPILACIÓN Y PRUEBA:

# Compilar
cd /workspaces/OsintUltimate/redteam_rust_core
cargo check

# Prueba rápida (asume que la herramienta está instalada)
RUST_LOG=debug cargo run -- --target example.com 2>&1 | grep $TOOL_NAME

# Deberías ver algo como:
# INFO redteam_rust_core: Tool 'arjun' detected at: /usr/bin/arjun
"

# ============================================================================
# PASO 5: BULK UPDATE (Para múltiples plugins)
# ============================================================================

echo "
🚀 ACTUALIZAR MÚLTIPLES PLUGINS EN UN COMANDO:

# Define los plugins a actualizar
plugins=(
  'src/plugins/enumeration/web/arjun.rs'
  'src/plugins/enumeration/web/gauplus.rs'
  'src/plugins/enumeration/web/whatweb.rs'
)

for plugin in \${plugins[@]}; do
  # 1. Agregar import si no existe
  if ! grep -q 'use crate::utils::tool_detection::detect_tool' \$plugin; then
    sed -i '/^use async_trait::async_trait;/i use crate::utils::tool_detection::detect_tool;' \$plugin
  fi
  
  # 2. Reemplazar en new()
  tool_name=\$(basename \$plugin .rs)
  sed -i \"s/which::which(\\\"$tool_name\\\").unwrap_or_else(|_| \\\"$tool_name\\\".into())/detect_tool(\\\"$tool_name\\\")/g\" \$plugin
  sed -i \"s/path.to_string_lossy().to_string(),/path,/g\" \$plugin
  
  # 3. Actualizar check_dependencies
  sed -i \"s/which::which(\\\"$tool_name\\\").is_ok()/crate::utils::check_tool_availability(\\\"$tool_name\\\").await/g\" \$plugin
  
  echo \"✅ Actualizado: \$plugin\"
done
"

# ============================================================================
# PASO 6: Documentación (Agregar a tabla)
# ============================================================================

echo "
📚 ACTUALIZAR DOCUMENTACIÓN:

Agregar a la tabla en docs/PLUGIN_DEVELOPMENT.md:

| arjun | ArjunScanner | enumeration/web | ✅ Integrado |
| gauplus | GauplusScanner | enumeration/web | ✅ Integrado |
| whatweb | WhatWebScanner | enumeration/web | ✅ Integrado |
"

# ============================================================================
# PASO 7: Arquitectura (Actualizar visualización)
# ============================================================================

echo "
🏗️  ACTUALIZAR VISUALIZACIÓN MODERNA:

En ARCHITECTURE_VISUALIZATION.sh, agregar a la sección BLACKARCH COMPATIBILITY:

│  ├─ arjun        (Parameter discovery) - Web enumeration
│  ├─ gauplus      (Golang port scanner) - Fast reconnaissance
│  └─ whatweb      (Web technology identifier) - Fingerprinting
"

cat << 'EOF'

═══════════════════════════════════════════════════════════════════════════════
✨ RESUMEN RÁPIDO - 3 PASOS PARA AGREGAR UNA HERRAMIENTA:

1. IMPORT:  Agregar "use crate::utils::tool_detection::detect_tool;"
2. NEW():   Cambiar "which::which()" → "detect_tool()"
3. CHECK:   Cambiar "which::which().is_ok()" → "check_tool_availability().await"

═══════════════════════════════════════════════════════════════════════════════

⏱️  TIEMPO ESTIMADO: 1-2 minutos por plugin
📊 PLUGINS DISPONIBLES PARA INTEGRAR: 15+
🎯 OBJETIVO: Soporte 100% de herramientas del sistema en v4.1

EOF
