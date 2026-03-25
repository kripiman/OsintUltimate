#!/bin/bash
# 🚀 INTEGRACIÓN MASIVA: BlackArch System Tools Integration v4.1
# Script para aplicar detección de herramientas a TODOS los plugins pendientes

echo "🔧 INICIANDO INTEGRACIÓN MASIVA DE BLACKARCH TOOLS"
echo "=================================================="

# Lista de plugins que necesitan actualización (todos los que usan which::which)
PLUGINS_TO_UPDATE=(
    "redteam_rust_core/src/plugins/exploitation/web/dalfox.rs"
    "redteam_rust_core/src/plugins/exploitation/web/graphql_cop.rs"
    "redteam_rust_core/src/plugins/exploitation/web/wapiti.rs"
    "redteam_rust_core/src/plugins/exploitation/web/jwt_tool.rs"
    "redteam_rust_core/src/plugins/exploitation/network/netexec.rs"
    "redteam_rust_core/src/plugins/exploitation/network/impacket.rs"
    "redteam_rust_core/src/plugins/exploitation/network/coercer.rs"
    "redteam_rust_core/src/plugins/exploitation/network/hydra.rs"
    "redteam_rust_core/src/plugins/exploitation/network/responder.rs"
    "redteam_rust_core/src/plugins/exploitation/network/petitpotam.rs"
    "redteam_rust_core/src/plugins/lateral_movement/bloodhound.rs"
    "redteam_rust_core/src/plugins/lateral_movement/ligolo.rs"
    "redteam_rust_core/src/plugins/lateral_movement/sliver.rs"
    "redteam_rust_core/src/plugins/persistence/havoc.rs"
    "redteam_rust_core/src/plugins/verification/zap.rs"
    "redteam_rust_core/src/plugins/verification/burp.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/dnsx.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/httpx.rs"
    "redteam_rust_core/src/plugins/reconnaissance/active/naabu.rs"
    "redteam_rust_core/src/plugins/reconnaissance/passive/trufflehog.rs"
    "redteam_rust_core/src/plugins/reconnaissance/passive/wayback.rs"
    "redteam_rust_core/src/plugins/reconnaissance/passive/gitleaks.rs"
    "redteam_rust_core/src/plugins/reconnaissance/osint/osint.rs"
    "redteam_rust_core/src/plugins/reconnaissance/osint/amass.rs"
    "redteam_rust_core/src/plugins/reconnaissance/osint/uncover.rs"
    "redteam_rust_core/src/plugins/reconnaissance/osint/subfinder.rs"
    "redteam_rust_core/src/plugins/enumeration/web/gauplus.rs"
    "redteam_rust_core/src/plugins/enumeration/web/web.rs"
    "redteam_rust_core/src/plugins/enumeration/web/arjun.rs"
    "redteam_rust_core/src/plugins/enumeration/web/nikto.rs"
    "redteam_rust_core/src/plugins/enumeration/web/snallygaster.rs"
    "redteam_rust_core/src/plugins/enumeration/web/crlfuzz.rs"
    "redteam_rust_core/src/plugins/enumeration/web/wpsec.rs"
    "redteam_rust_core/src/plugins/enumeration/web/katana.rs"
    "redteam_rust_core/src/plugins/enumeration/web/tsunami.rs"
    "redteam_rust_core/src/plugins/enumeration/web/kiterunner.rs"
    "redteam_rust_core/src/plugins/enumeration/web/interactsh.rs"
    "redteam_rust_core/src/plugins/enumeration/web/feroxbuster.rs"
    "redteam_rust_core/src/plugins/enumeration/web/whatweb.rs"
    "redteam_rust_core/src/plugins/enumeration/web/gowitness.rs"
    "redteam_rust_core/src/plugins/enumeration/web/gf.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/kubebench.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudenum.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudbrute.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/cloudfox.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/pacu.rs"
    "redteam_rust_core/src/plugins/enumeration/cloud/prowler.rs"
    "redteam_rust_core/src/plugins/enumeration/network/net.rs"
    "redteam_rust_core/src/plugins/compliance/checkov.rs"
    "redteam_rust_core/src/plugins/compliance/trivy.rs"
    "redteam_rust_core/src/plugins/compliance/osv_scanner.rs"
    "redteam_rust_core/src/plugins/compliance/kubescape.rs"
    "redteam_rust_core/src/plugins/intelligence/searchsploit.rs"
    "redteam_rust_core/src/plugins/intelligence/jaeles.rs"
    "redteam_rust_core/src/plugins/privilege_escalation/certipy.rs"
    "redteam_rust_core/src/plugins/ffi.rs"
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

    echo "🔄 Procesando: $plugin"

    # 1. Agregar import si no existe
    if ! grep -q 'use crate::utils::tool_detection::detect_tool' "$plugin"; then
        # Buscar la línea de async_trait para insertar antes
        if grep -q '^use async_trait::async_trait;' "$plugin"; then
            sed -i '/^use async_trait::async_trait;/i use crate::utils::tool_detection::detect_tool;' "$plugin"
            echo "  ✅ Import agregado"
        else
            # Si no hay async_trait, agregar al principio después de otros imports
            sed -i '1a use crate::utils::tool_detection::detect_tool;' "$plugin"
            echo "  ✅ Import agregado (método alternativo)"
        fi
    else
        echo "  ℹ️  Import ya existe"
    fi

    # 2. Reemplazar en new() - patrón general
    # Buscar patrones comunes de which::which
    sed -i 's/which::which(\([^)]*\))\.unwrap_or_else(|_| \1\.into())/detect_tool(\1)/g' "$plugin"
    sed -i 's/which::which(\([^)]*\))\.or_else(|_| which::which("[^"]*"))/detect_tool(\1)/g' "$plugin"
    sed -i 's/which::which(\([^)]*\))\.to_string_lossy()\.to_string()/detect_tool(\1)/g' "$plugin"

    # 3. Reemplazar en check_dependencies
    sed -i 's/which::which(\([^)]*\))\.is_ok()/crate::utils::check_tool_availability(\1).await/g' "$plugin"

    # 4. Verificar cambios
    if grep -q 'detect_tool(' "$plugin" && grep -q 'check_tool_availability(' "$plugin"; then
        echo "  ✅ Plugin actualizado exitosamente"
        ((UPDATED_COUNT++))
    else
        echo "  ⚠️  Verificación pendiente - revisar manualmente"
    fi

    echo ""
done

echo "=================================================="
echo "📊 RESUMEN DE INTEGRACIÓN MASIVA"
echo "=================================================="
echo "✅ Plugins actualizados exitosamente: $UPDATED_COUNT"
echo "❌ Plugins con errores: $FAILED_COUNT"
echo "📈 Tasa de éxito: $(( (UPDATED_COUNT * 100) / TOTAL_PLUGINS ))%"
echo ""
echo "🔍 VERIFICACIÓN MANUAL RECOMENDADA:"
echo "  - Revisar algunos plugins aleatorios"
echo "  - Ejecutar 'cargo check' para validar sintaxis"
echo "  - Probar con herramientas instaladas"
echo ""
echo "📚 PRÓXIMOS PASOS:"
echo "  - Actualizar documentación con lista completa"
echo "  - Agregar caché de detecciones"
echo "  - Implementar UI para mostrar estado de herramientas"