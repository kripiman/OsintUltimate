# PAYLOAD_BLOCK_START
# SAFETY_WARNING: SOLO ejecutar en LAB_VM=TRUE; TARGET=ISOLATED
# FILENAME: plugins/stealth_hell_mode.py
"""
PLUGIN: Hell Mode Scanner
Técnicas: Jitter Temporal (T1027), Masquerading (T1036), Session Pinning.
"""
import time
import random
import requests
import urllib3
# Se asume que intelligence_core_v3.py está en el directorio superior
from intelligence_core_v3 import BasePlugin, Asset

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HellModeScanner(BasePlugin):
    def __init__(self):
        # Jitter: Intervalos humanos para romper análisis de frecuencia
        self.min_delay = 2.5
        self.max_delay = 8.0
        self.timeout = 15 
        
        # Perfiles de Identidad (Session Pinning)
        # Una vez elegido un perfil, se mantiene hasta terminar con el host.
        self.profiles = [
            {
                "name": "Chrome_Win10",
                "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            },
            {
                "name": "Safari_Mac",
                "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        ]

        # Firmas de alto impacto (High Impact, Low Noise)
        self.signatures = [
            ("/.env", "APP_KEY=", "CRITICAL: Laravel Config"),
            ("/wp-config.php.bak", "DB_PASSWORD", "CRITICAL: WP Backup"),
            ("/.git/config", "repositoryformatversion", "HIGH: Git Exposed"),
            ("/.aws/credentials", "aws_access_key_id", "CRITICAL: AWS Keys")
        ]

    def _sleep_jitter(self):
        time.sleep(random.uniform(self.min_delay, self.max_delay))

    def _get_consistent_headers(self, profile, target_url):
        try:
            domain = target_url.split("/")[2]
        except IndexError:
            domain = "localhost"

        return {
            "User-Agent": profile["ua"],
            "Accept": profile["accept"],
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Referer": f"https://{domain}/", # Mimetismo: "Venimos del Home"
        }

    def enrich_asset(self, asset: Asset) -> Asset:
        if not asset.ip: return asset
        
        # 1. Asignar Identidad Única para esta sesión
        session_profile = random.choice(self.profiles)
        
        # 2. Iniciar Sesión Persistente (TCP Keep-Alive + Cookies)
        with requests.Session() as session:
            
            for endpoint, signature, title in self.signatures:
                target_url = f"{asset.url.rstrip('/')}{endpoint}"
                
                # Pausa Táctica
                self._sleep_jitter()
                
                try:
                    headers = self._get_consistent_headers(session_profile, target_url)
                    
                    resp = session.get(
                        target_url,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False,
                        stream=True 
                    )
                    
                    # Evasión básica de WAF (Rate Limit detectado)
                    if resp.status_code == 429:
                        break 
                        
                    if resp.status_code == 200:
                        content = resp.raw.read(4096).decode('utf-8', errors='ignore')
                        
                        if signature in content and "not found" not in content.lower():
                            asset.risk.score += 20
                            asset.risk.severity = "CRITICAL"
                            asset.risk.vectors.append("Stealth_HellMode")
                            asset.risk.reasons.append(f"{title} (Profile: {session_profile['name']})")
                            
                            # ESTRATEGIA: Parar al primer hallazgo crítico para mantener silencio
                            break 

                except Exception:
                    pass # Silencio absoluto en errores

        return asset

def init_plugin():
    return HellModeScanner()
# PAYLOAD_BLOCK_END