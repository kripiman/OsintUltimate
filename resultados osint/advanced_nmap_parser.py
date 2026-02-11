#!/usr/bin/env python3
"""
ADVANCED NMAP PARSER v2.0
Nivel: 7/10 (Sólido/Profesional)
Uso: Convierte salidas .gnmap (Nmap Grepable) en una lista limpia de objetivos web.
     Ideal para recuperar sesiones de escaneo interrumpidas o procesar datos manuales.
"""
import re
import sys
import argparse
from typing import Set, Generator

class NmapParser:
    def __init__(self):
        # Regex optimizado para capturar IP y el bloque de puertos del formato -oG
        self.host_regex = re.compile(r'Host: ([0-9.]+)')
        self.ports_regex = re.compile(r'Ports: (.*)')
        
        # Servicios que indican forzosamente HTTPS (SSL/TLS)
        self.ssl_services = {'https', 'ssl', 'https-alt', 'ssl/http', '443/tcp'}

    def _determine_scheme(self, port: str, service: str) -> str:
        """
        Decisión inteligente de protocolo (HTTP vs HTTPS).
        Prioriza la detección de servicio de Nmap sobre el número de puerto.
        """
        # 1. Prioridad: Lo que Nmap detectó explícitamente en el servicio
        if any(s in service.lower() for s in self.ssl_services):
            return 'https'
        
        # 2. Fallback: Puertos estándar conocidos por usar SSL
        if port in ['443', '8443', '9443', '10443']:
            return 'https'
            
        # 3. Default: Asumimos HTTP plano
        return 'http'

    def _normalize_url(self, scheme: str, ip: str, port: str) -> str:
        """
        Limpia URLs redundantes para estándares web.
        Ej: Convierte 'http://1.2.3.4:80' -> 'http://1.2.3.4'
        """
        if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
            return f"{scheme}://{ip}"
        return f"{scheme}://{ip}:{port}"

    def parse_file(self, filepath: str) -> Generator[str, None, None]:
        """
        Generador eficiente que lee el archivo línea por línea.
        No carga todo el archivo en RAM, ideal para logs grandes.
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Ignoramos líneas que no tengan información de puertos abiertos
                    if "Ports:" not in line or "Status:" in line:
                        continue

                    ip_match = self.host_regex.search(line)
                    ports_match = self.ports_regex.search(line)

                    if not ip_match or not ports_match:
                        continue

                    ip = ip_match.group(1)
                    ports_data = ports_match.group(1)

                    # El formato GNMAP separa puertos por coma: 
                    # 80/open/tcp//http///, 443/open/tcp//https///
                    for port_entry in ports_data.split(','):
                        fields = port_entry.strip().split('/')
                        if len(fields) < 5: continue

                        port_num = fields[0]
                        state = fields[1]
                        service = fields[4]

                        # Solo nos interesan puertos abiertos
                        if state == 'open':
                            scheme = self._determine_scheme(port_num, service)
                            yield self._normalize_url(scheme, ip, port_num)

        except FileNotFoundError:
            print(f"❌ Error: Archivo no encontrado: {filepath}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error crítico parseando: {e}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Advanced Nmap to URL Parser")
    parser.add_argument("input_file", help="Archivo .gnmap o .txt con output grepable de Nmap")
    parser.add_argument("-o", "--output", default="web_targets_parsed.txt", help="Archivo de salida")
    args = parser.parse_args()

    parser_tool = NmapParser()
    unique_targets: Set[str] = set()

    print(f"[*] Analizando {args.input_file}...")
    
    count = 0
    # Usamos el generador para poblar un set y evitar duplicados automáticamente
    for url in parser_tool.parse_file(args.input_file):
        unique_targets.add(url)
        count += 1

    # Guardar resultados
    try:
        with open(args.output, 'w') as f:
            for url in sorted(unique_targets):
                f.write(f"{url}\n")
    except IOError as e:
        print(f"❌ Error escribiendo salida: {e}")
        sys.exit(1)

    print(f"✅ Procesados {count} puertos abiertos.")
    print(f"✅ Generados {len(unique_targets)} objetivos web únicos.")
    print(f"💾 Guardado en: {args.output}")

if __name__ == "__main__":
    main()