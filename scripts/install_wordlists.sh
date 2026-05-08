#!/bin/bash
# 🔱 Mimikri V14.3 - Wordlist & Resolvers Provisioning Script
# Propósito: Automatizar la descarga de "munición" para el Arsenal P0.

set -e

# Configuración de directorios
WORDLISTS_DIR="$HOME/.local/share/osint-ultimate/wordlists"
echo "📂 Preparando directorio de diccionarios: $WORDLISTS_DIR"
mkdir -p "$WORDLISTS_DIR"

# 1. SecLists (El corazón del OSINT)
echo "🚀 Clonando SecLists (danielmiessler)..."
if [ ! -d "$WORDLISTS_DIR/seclists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLISTS_DIR/seclists"
else
    echo "✅ SecLists ya existe. Actualizando..."
    cd "$WORDLISTS_DIR/seclists" && git pull
    cd -
fi

# 2. Trickest Resolvers (Indispensable para ShuffleDNS/MassDNS)
echo "🛰️ Descargando Resolvers actualizados (trickest)..."
curl -L -o "$WORDLISTS_DIR/resolvers.txt" \
    https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# 3. Assetnote (DNS de alta escala)
echo "⚡ Descargando Assetnote Best DNS wordlist..."
curl -L -o "$WORDLISTS_DIR/best-dns-wordlist.txt" \
    https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# 4. N0kovo Subdomains (Dataset 2024-2025 optimizado)
echo "🆕 Descargando n0kovo subdomains (Huge)..."
curl -L -o "$WORDLISTS_DIR/n0kovo-subdomains.txt" \
    https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt

echo -e "\n✅ PROVISIÓN COMPLETADA."
echo "Rutas recomendadas para tu .env:"
echo "--------------------------------"
echo "SHUFFLEDNS_WORDLIST=$WORDLISTS_DIR/n0kovo-subdomains.txt"
echo "SHUFFLEDNS_RESOLVERS=$WORDLISTS_DIR/resolvers.txt"
echo "S3SCANNER_WORDLIST=$WORDLISTS_DIR/seclists/Discovery/Cloud/cloud_buckets_full.txt"
echo "CLAIRVOYANCE_WORDLIST=$WORDLISTS_DIR/seclists/Discovery/Web-Content/graphql.txt"
echo "--------------------------------"
