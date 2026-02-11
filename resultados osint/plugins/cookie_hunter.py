"""
PLUGIN: Cookie Hunter
Analiza headers (si están disponibles) para detectar cookies inseguras.
Requiere que el scanner original haya capturado headers o hace un fetch rápido.
"""
from urllib.request import urlopen, Request
from intelligence_core_v3 import BasePlugin, Asset

class CookieHunter(BasePlugin):
    def enrich_asset(self, asset: Asset) -> Asset:
        # Solo escaneamos activos que parezcan interesantes (Score > 0) para ahorrar tiempo
        if asset.risk.score < 1:
            return asset

        try:
            # Hacemos una petición HEAD rápida para ver cookies
            req = Request(asset.url, method='HEAD', headers={"User-Agent": "AcademicScanner/1.0"})
            with urlopen(req, timeout=2) as resp:
                cookies = resp.headers.get_all('Set-Cookie')
                if cookies:
                    for c in cookies:
                        c_lower = c.lower()
                        issues = []
                        if "httponly" not in c_lower:
                            issues.append("No-HttpOnly")
                        if "secure" not in c_lower and asset.url.startswith("https"):
                            issues.append("No-Secure")
                        
                        if issues:
                            asset.risk.score += 2
                            asset.risk.vectors.append("Insecure_Cookies")
                            asset.risk.reasons.append(f"Cookie flags missing: {','.join(issues)}")
                            break # Basta con encontrar una mala
        except Exception:
            pass # Silencioso si falla
            
        return asset

def init_plugin():
    return CookieHunter()