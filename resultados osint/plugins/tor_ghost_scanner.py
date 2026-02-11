# PAYLOAD_BLOCK_START
# SAFETY_WARNING: SOLO ejecutar en LAB_VM=TRUE; TARGET=ISOLATED
# FILENAME: plugins/tor_ghost_scanner.py
"""
PLUGIN: Tor Ghost Scanner
Técnicas: Proxy Multi-hop (T1090.003), Remote DNS Resolution.
"""
import time
import random
import requests
import urllib3
from intelligence_core_v3 import BasePlugin, Asset

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TorScanner(BasePlugin):
    def __init__(self):
        # CRÍTICO: 'socks5h://' delega la resolución DNS al nodo de salida de Tor.
        # Si usas 'socks5://', tu ISP verá las peticiones DNS.
        self.tor_proxy = "socks5h://127.0.0.1:9050" 
        self.timeout = 30 # Latencia alta esperada en Tor
        
        # User-Agent mimetizado con Tor Browser Bundle (Windows/Firefox ESR)
        self.tor_ua = "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0"

        self.signatures = [
            ("/.env", "APP_KEY=", "CRITICAL: Laravel Config"),
            ("/wp-config.php.bak", "DB_PASSWORD", "CRITICAL: WP Backup"),
            ("/id_rsa", "BEGIN RSA PRIVATE KEY", "CRITICAL: SSH Key")
        ]

    def enrich_asset(self, asset: Asset) -> Asset:
        if not asset.ip: return asset

        proxies = {
            "http": self.tor_proxy,
            "https": self.tor_proxy
        }
        
        headers = {
            "User-Agent": self.tor_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive" # Intentar mantener el circuito
        }

        try:
            with requests.Session() as session:
                session.proxies.update(proxies)
                session.headers.update(headers)
                
                for endpoint, signature, title in self.signatures:
                    target_url = f"{asset.url.rstrip('/')}{endpoint}"
                    
                    # Pequeño jitter, aunque Tor ya añade latencia variable
                    time.sleep(random.uniform(1.0, 3.0))
                    
                    resp = session.get(
                        target_url,
                        timeout=self.timeout,
                        verify=False,
                        stream=True
                    )
                    
                    if resp.status_code == 200:
                        content = resp.raw.read(4096).decode('utf-8', errors='ignore')
                        if signature in content:
                            asset.risk.score += 20
                            asset.risk.severity = "CRITICAL"
                            asset.risk.vectors.append("Tor_Ghost")
                            asset.risk.reasons.append(f"{title} (Anonimizado)")
                            break
                            
        except requests.exceptions.ConnectionError:
            pass # Fallos de circuito Tor son comunes
        except Exception:
            pass

        return asset

def init_plugin():
    return TorScanner()
# PAYLOAD_BLOCK_END