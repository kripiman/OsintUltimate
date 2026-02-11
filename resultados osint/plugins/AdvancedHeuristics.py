"""
PLUGIN: Heurística Avanzada (The Brain)
Añade lógica de detección de anomalías y fingerprinting profundo.
"""
import re
# [CORRECCIÓN CRÍTICA] Eliminamos 'init_plugin' de aquí. Solo importamos las clases base.
from intelligence_core_v3 import BasePlugin, Asset

class AdvancedHeuristics(BasePlugin):
    def enrich_asset(self, asset: Asset) -> Asset:
        
        # 1. Detección de WAF por comportamiento (403 + Tecnologías conocidas)
        # Lógica: Si está prohibido pero 'habla' (headers/tech), hay un WAF/Firewall.
        if asset.status == 403 and len(asset.tech) > 0:
            asset.risk.score += 5
            asset.risk.vectors.append("Potential_WAF_Block")
            asset.risk.reasons.append("Tech detected behind 403 Forbidden")

        # 2. Análisis de Entalpía del Título (Detectar errores de stack trace expuestos)
        # [MEJORA DE SEGURIDAD] Verificamos "if asset.title" para evitar crash si es None
        if asset.title and len(asset.title) > 50:
            keywords = ['error', 'exception', 'stack', 'line', 'trace', 'syntax']
            if any(x in asset.title.lower() for x in keywords):
                asset.risk.score += 10
                asset.risk.severity = "HIGH"
                asset.risk.vectors.append("Info_Leakage")
                asset.risk.reasons.append("Stack Trace/Error expuesto en título")

        # 3. Detección de Paneles Administrativos Ocultos
        # Verificamos que asset.url exista antes de buscar
        if asset.url and ("login" in asset.url or "admin" in asset.url):
             # Si además usa SSL inválido o tecnologías enterprise pesadas
            if not asset.ssl_issuer or "WSO2" in asset.tech or "JBoss" in asset.tech:
                asset.risk.score += 8
                # Sugerimos tomar captura de pantalla como evidencia académica
                asset.risk.suggested_commands.insert(0, f"screenshot_url {asset.url}")
                asset.risk.reasons.append("Critical Admin Panel (Insecure/Enterprise)")

        # 4. Fingerprinting de Desarrollo/Staging
        # [MEJORA] Agregamos variantes con punto (.) ej: dev.sitio.com
        staging_keywords = ['dev-', 'test-', 'uat-', 'staging', 'dev.', 'test.', 'uat.', 'beta.']
        if any(x in asset.domain for x in staging_keywords):
            asset.risk.score += 4
            asset.risk.vectors.append("Non-Production_Environment")
            asset.risk.reasons.append("Entorno de pruebas (posiblemente menos seguro)")

        return asset

# Esta función es la que el Core busca. NO debe ser importada arriba.
def init_plugin():
    return AdvancedHeuristics()