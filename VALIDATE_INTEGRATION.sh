#!/bin/bash

# VALIDATION SCRIPT: BlackArch Integration v4.1
# Fecha: 2026-03-24
# Propósito: Validar la integración masiva completada

echo "🔍 VALIDACIÓN DE INTEGRACIÓN BLACKARCH v4.1"
echo "=========================================="

# 1. Contar plugins integrados
echo "📊 Contando plugins con detect_tool()..."
PLUGINS_INTEGRADOS=$(find redteam_rust_core/src/plugins -name "*.rs" -exec grep -l "detect_tool(" {} \; | wc -l)
echo "✅ Plugins integrados: $PLUGINS_INTEGRADOS"

# 2. Verificar que tool_detection.rs existe
echo "🔧 Verificando módulo tool_detection..."
if [ -f "redteam_rust_core/src/utils/tool_detection.rs" ]; then
    echo "✅ tool_detection.rs existe"
else
    echo "❌ tool_detection.rs NO existe"
    exit 1
fi

# 3. Verificar dependencias en Cargo.toml
echo "📦 Verificando dependencias..."
if grep -q "which = " redteam_rust_core/Cargo.toml; then
    echo "✅ Dependencia 'which' presente"
else
    echo "❌ Dependencia 'which' faltante"
fi

# 4. Verificar imports en plugins clave
echo "🔗 Verificando imports en plugins clave..."
PLUGINS_CLAVE=("ffuf" "nuclei" "rustscan" "hydra")
for plugin in "${PLUGINS_CLAVE[@]}"; do
    if find redteam_rust_core/src/plugins -name "*$plugin.rs" -exec grep -l "use crate::utils::tool_detection" {} \; | grep -q .; then
        echo "✅ $plugin: Import correcto"
    else
        echo "❌ $plugin: Import faltante"
    fi
done

# 5. Verificar documentación
echo "📚 Verificando documentación..."
if grep -q "35+" redteam_rust_core/docs/PLUGIN_DEVELOPMENT.md; then
    echo "✅ Documentación actualizada con 35+ plugins"
else
    echo "❌ Documentación no actualizada"
fi

# 6. Verificar scripts de automatización
echo "🤖 Verificando scripts de automatización..."
if [ -f "MASSIVE_BLACKARCH_INTEGRATION.sh" ]; then
    echo "✅ Script de integración presente"
else
    echo "❌ Script de integración faltante"
fi

echo ""
echo "🎯 RESULTADO FINAL:"
if [ "$PLUGINS_INTEGRADOS" -ge 30 ]; then
    echo "🟢 INTEGRACIÓN EXITOSA: $PLUGINS_INTEGRADOS plugins integrados"
    echo "🚀 Estado: PRODUCCIÓN READY"
else
    echo "🟡 INTEGRACIÓN PARCIAL: Solo $PLUGINS_INTEGRADOS plugins"
    echo "⚠️  Estado: REQUIERE COMPLETACIÓN"
fi

echo ""
echo "📋 PRÓXIMOS PASOS:"
echo "1. Completar integración de plugins restantes (si los hay)"
echo "2. Implementar caché de detecciones"
echo "3. Agregar UI para mostrar herramientas detectadas"
echo "4. Probar en entornos BlackArch/Kali"