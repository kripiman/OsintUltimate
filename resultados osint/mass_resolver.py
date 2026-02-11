#!/usr/bin/env python3
"""
MASS RESOLVER v2.0 - High Performance DNS Extraction
Nivel: 9/10 (AsyncIO Puro)
Uso: Convierte listas de dominios en IPs únicas listas para escanear.
"""
import asyncio
import aiohttp
import sys
import socket
import argparse
import ipaddress
from collections import defaultdict
from typing import List, Dict, Set

# Configuración de Colores
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class AsyncDNSResolver:
    def __init__(self, concurrency: int = 100):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = defaultdict(list) # IP -> [Domain1, Domain2]
        self.errors = []
        self.cdn_ranges = [
            # Ejemplo simplificado de rangos a ignorar (Cloudflare, etc)
            # En un entorno real, usarías una lista más completa
        ]

    async def resolve_domain(self, domain: str):
        """Resuelve un dominio a IP de forma asíncrona"""
        async with self.semaphore:
            try:
                loop = asyncio.get_running_loop()
                # getaddrinfo es no-bloqueante cuando se usa con el loop
                # Port 80 es dummy, solo queremos la IP
                info = await loop.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
                
                # Extraer IPs únicas (puede devolver IPv4 e IPv6)
                ips = set()
                for rec in info:
                    ip = rec[4][0]
                    ips.add(ip)
                
                return domain, list(ips)
            except socket.gaierror:
                return domain, None
            except Exception as e:
                self.errors.append((domain, str(e)))
                return domain, None

    async def process_batch(self, domains: List[str]):
        print(f"{Colors.HEADER}[*] Iniciando resolución masiva de {len(domains)} dominios...{Colors.ENDC}")
        
        tasks = [self.resolve_domain(d) for d in domains]
        completed = 0
        total = len(domains)
        
        # Procesar a medida que terminan
        for future in asyncio.as_completed(tasks):
            domain, ips = await future
            completed += 1
            
            if ips:
                for ip in ips:
                    self.results[ip].append(domain)
                print(f"\r{Colors.GREEN}[+] Resuelto: {domain} -> {ips}{Colors.ENDC}", end="", flush=True)
            else:
                print(f"\r{Colors.FAIL}[-] Falló: {domain}{Colors.ENDC}", end="", flush=True)
                
        print(f"\n\n{Colors.BLUE}[*] Resolución completada.{Colors.ENDC}")

    def export_unique_ips(self, filename: str):
        """Guarda solo las IPs únicas para herramientas como Nmap"""
        unique_ips = list(self.results.keys())
        with open(filename, 'w') as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")
        return len(unique_ips)

    def print_summary(self):
        print(f"{Colors.HEADER}--- RESUMEN DE INFRAESTRUCTURA ---{Colors.ENDC}")
        print(f"Dominios procesados: {sum(len(v) for v in self.results.values()) + len(self.errors)}")
        print(f"IPs Únicas descubiertas: {len(self.results)}")
        
        # Detectar Hosts Compartidos (Virtual Hosting)
        print(f"\n{Colors.WARNING}[!] Hosts Compartidos Detectados (Virtual Hosting):{Colors.ENDC}")
        for ip, domains in self.results.items():
            if len(domains) > 1:
                print(f"  IP {ip} aloja {len(domains)} dominios: {', '.join(domains[:3])}...")

async def main():
    parser = argparse.ArgumentParser(description="Mass DNS Resolver (Async)")
    parser.add_argument("input", help="Archivo con lista de dominios (uno por línea)")
    parser.add_argument("-o", "--output", default="ips_objetivo.txt", help="Archivo de salida para IPs únicas")
    args = parser.parse_args()

    # Leer dominios
    try:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: Archivo no encontrado")
        sys.exit(1)

    resolver = AsyncDNSResolver()
    
    # Iniciar motor async
    start_time = asyncio.get_running_loop().time()
    await resolver.process_batch(domains)
    duration = asyncio.get_running_loop().time() - start_time

    # Reporte
    count = resolver.export_unique_ips(args.output)
    resolver.print_summary()
    
    print(f"\n{Colors.GREEN}✅ IPs guardadas en: {args.output}")
    print(f"⚡ Tiempo total: {duration:.2f} segundos{Colors.ENDC}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass