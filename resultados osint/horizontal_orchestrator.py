# PAYLOAD_BLOCK_START
# SAFETY_WARNING: SOLO ejecutar en LAB_VM=TRUE; TARGET=ISOLATED
# FILENAME: horizontal_orchestrator.py
"""
CONTROLLER: Horizontal Orchestrator
Objetivo: Ejecución asíncrona de escaneos bloqueantes (Hell Mode)
para lograr velocidad global mediante paralelismo horizontal.
"""
import asyncio
import sys
import logging
from typing import List

# Importamos el plugin Hell Mode (asegúrate de que esté en el PYTHONPATH)
# Ojo: Aquí simulamos la importación para que el código sea autocontenido en la demo
try:
    from plugins.stealth_hell_mode import HellModeScanner
    from intelligence_core_v3 import Asset, RiskProfile 
except ImportError:
    # Mocks para que el código compile si faltan archivos
    class RiskProfile: 
        def __init__(self): 
            self.score=0; self.reasons=[]
    class Asset: 
        def __init__(self): 
            self.url=""; self.ip="0.0.0.0"; self.risk=RiskProfile()
    class HellModeScanner:
        def enrich_asset(self, a): return a

# Configuración
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("Orchestrator")

class HorizontalOrchestrator:
    def __init__(self, targets: List[str], concurrency=20):
        self.targets = targets
        # Semáforo: Controla cuántos 'Francotiradores' actúan a la vez
        self.semaphore = asyncio.Semaphore(concurrency) 
        self.scanner_plugin = HellModeScanner() 

    async def _scan_target_wrapper(self, url: str):
        """
        Envuelve el escaneo síncrono/bloqueante en un hilo de ejecución
        para no detener el Event Loop asíncrono.
        """
        async with self.semaphore:
            # Crear Asset Dummy
            asset = Asset() 
            asset.url = url
            asset.ip = "192.168.x.x" # IP placeholder, el plugin resolverá o usará URL
            asset.risk = RiskProfile()

            # logger.info(f"[*] Lanzando agente contra: {url}")
            
            # MAGIA ASÍNCRONA:
            # loop.run_in_executor mueve la tarea bloqueante (requests + time.sleep)
            # a un ThreadPool separado. Esto permite que el 'asyncio loop' siga
            # lanzando otros agentes mientras este duerme.
            loop = asyncio.get_running_loop()
            
            try:
                # Ejecutamos el plugin 'lento'
                await loop.run_in_executor(None, self.scanner_plugin.enrich_asset, asset)
                
                if asset.risk.score > 0:
                    logger.warning(f"🚨 [VULN] {url} -> {asset.risk.reasons}")
                else:
                    # Opcional: Feedback de progreso
                    print(f".", end="", flush=True) 
                    
            except Exception as e:
                logger.error(f"Error en {url}: {e}")

    async def run(self):
        logger.info(f"🚀 Iniciando ataque horizontal contra {len(self.targets)} objetivos...")
        tasks = [self._scan_target_wrapper(url) for url in self.targets]
        await asyncio.gather(*tasks)
        print("\n✅ Orquestación finalizada.")

if __name__ == "__main__":
    # Ejemplo de uso: python3 horizontal_orchestrator.py targets.txt
    if len(sys.argv) < 2:
        # Modo Demo
        targets = [f"http://192.168.1.{i}" for i in range(100, 120)]
    else:
        with open(sys.argv[1]) as f:
            targets = [l.strip() for l in f if l.strip()]
            
    orchestrator = HorizontalOrchestrator(targets, concurrency=50)
    
    # En Windows suele requerir política de loop específica, en Linux standard va bien
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        print("\n🛑 Abortado por operador.")
# PAYLOAD_BLOCK_END