#!/bin/bash
# 🚀 INTEGRACIÓN MASIVA MEJORADA: BlackArch System Tools Integration v4.1
# Versión mejorada que maneja todos los patrones de which::which

echo "🔧 INICIANDO INTEGRACIÓN MASIVA MEJORADA"
echo "=========================================="

# Función para actualizar un plugin individual
update_plugin() {
    local plugin="$1"
    echo "🔄 Procesando: $plugin"

    # 1. Agregar import si no existe
    if ! grep -q 'use crate::utils::tool_detection::detect_tool' "$plugin"; then
        if grep -q '^use async_trait::async_trait;' "$plugin"; then
            sed -i '/^use async_trait::async_trait;/i use crate::utils::tool_detection::detect_tool;' "$plugin"
        else
            sed -i '1a use crate::utils::tool_detection::detect_tool;' "$plugin"
        fi
        echo "  ✅ Import agregado"
    fi

    # 2. Reemplazar patrones en new() - múltiples intentos para diferentes patrones

    # Patrón 1: which::which("tool").unwrap_or_else(|_| "tool".into())
    sed -i 's/which::which("\([^"]*\)").unwrap_or_else(|_| "\1".into())/detect_tool("\1")/g' "$plugin"

    # Patrón 2: which::which("tool").or_else(|_| which::which("fallback"))
    sed -i 's/which::which("\([^"]*\)").or_else(|_| which::which("[^"]*")).unwrap_or_else(|_| "[^"]*".into())/detect_tool("\1")/g' "$plugin"

    # Patrón 3: which::which("tool").or_else(|_| which::which("fallback")) sin unwrap
    sed -i 's/which::which("\([^"]*\)").or_else(|_| which::which("[^"]*"))/detect_tool("\1")/g' "$plugin"

    # Patrón 4: Solo which::which("tool") sin or_else
    sed -i 's/let path = which::which("\([^"]*\)");/let path = detect_tool("\1");/g' "$plugin"

    # Patrón 5: which::which("tool").to_string_lossy().to_string()
    sed -i 's/which::which("\([^"]*\)").to_string_lossy().to_string()/detect_tool("\1")/g' "$plugin"

    # 3. Reemplazar en check_dependencies
    sed -i 's/which::which("\([^"]*\)").is_ok()/crate::utils::check_tool_availability("\1").await/g' "$plugin"

    # 4. Limpiar líneas vacías extras que puedan haber quedado
    sed -i '/^[[:space:]]*$/d' "$plugin"

    # 5. Verificar cambios
    if grep -q 'detect_tool(' "$plugin" || grep -q 'check_tool_availability(' "$plugin"; then
        echo "  ✅ Plugin actualizado"
        return 0
    else
        echo "  ⚠️  Sin cambios detectados - revisar manualmente"
        return 1
    fi
}

# Lista de plugins que aún necesitan actualización
PLUGINS_TO_UPDATE=(
    "redteam_rust_core/src/plugins/exploitation/network/netexec.rs"
    "redteam_rust_core/src/plugins/exploitation/network/coercer.rs"
    "redteam_rust_core/src/plugins/exploitation/network/responder.rs"
    "redteam_rust_core/src/plugins/exploitation/network/petitpotam.rs"
    "redteam_rust_core/src/plugins/lateral_movement/bloodhound.rs"
    "redteam_rust_core/src/plugins/lateral_movement/ligolo.rs"
    "redteam_rust_core/src/plugins/lateral_movement/sliver.rs"
    "redteam_rust_core/src/plugins/persistence/havoc.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/dnsx.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/httpx.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/naabu.rs"
    "redteam_rust_core/src/plugins/reconnaissance/passive/wayback.rs"
    "redteam_rust_core/src/plugins/reconnaissance/osint/uncover.rs"
    "redteam_rust_core/src/plugins/enumeration/web/gauplus.rs"
    "redteam_rust_core/src/plugins/enumeration/web/interactsh.rs"
    "redteam_rust_core/src/plugins/enumeration/web/feroxbuster.rs"
    "redteam_rust_core/src/plugins/enumeration/web/gowitness.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudenum.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudbrute.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudfox.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/pacu.rs"
    "redteam_rust_core/src/plugins/compliance/trivy.rs"
    "redteam_rust_core/src/plugins/intelligence/searchsploit.rs"
    "redteam_rust_core/src/plugins/privilege_escalation/certipy.rs"
)

TOTAL_PLUGINS=${#PLUGINS_TO_UPDATE[@]}
UPDATED_COUNT=0
FAILED_COUNT=0

echo "📊 TOTAL DE PLUGINS A ACTUALIZAR: $TOTAL_PLUGINS"
echo ""

for plugin in "${PLUGINS_TO_UPDATE[@]}"; do
    if [ ! -f "$plugin" ]; then
        echo "❌ ERROR: Plugin no encontrado: $plugin"
        ((FAILED_COUNT++))
        continue
    fi

    if update_plugin "$plugin"; then
        ((UPDATED_COUNT++))
    else
        ((FAILED_COUNT++))
    fi
    echo ""
done

echo "=========================================="
echo "📊 RESUMEN DE INTEGRACIÓN MEJORADA"
echo "=========================================="
echo "✅ Plugins actualizados exitosamente: $UPDATED_COUNT"
echo "❌ Plugins con errores: $FAILED_COUNT"
echo "📈 Tasa de éxito: $(( (UPDATED_COUNT * 100) / TOTAL_PLUGINS ))%"
echo ""
echo "🔍 VERIFICACIÓN:"
echo "  - Plugins con detect_tool: $(find redteam_rust_core/src/plugins -name "*.rs" -exec grep -l "detect_tool(" {} \; | wc -l)"
echo "  - Plugins con which::which: $(find redteam_rust_core/src/plugins -name "*.rs" -exec grep -l "which::which" {} \; | wc -l)"
echo ""
echo "🎯 TOTAL DE PLUGINS INTEGRADOS: $(find redteam_rust_core/src/plugins -name "*.rs" -exec grep -l "detect_tool(" {} \; | wc -l)"