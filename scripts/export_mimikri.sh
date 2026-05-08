#!/bin/bash
# scripts/export_mimikri.sh
# Automatiza la exportación de OsintUltimate al repositorio sanitizado 'mimikri'.
# Versión corregida (Auditoría Kimi 2.0)

set -e

SOURCE_DIR=$(pwd)
DEST_DIR=$(realpath "$SOURCE_DIR/../mimikri")

echo "🚀 Iniciando exportación a $DEST_DIR..."

# 1. Crear directorio de destino
mkdir -p "$DEST_DIR"

# 2. Definir exclusiones (Cumpliendo con la auditoría)
EXCLUDES=(
    ".git"
    ".env"
    ".env.oracle"
    ".env.production"
    "target"
    "node_modules"
    "venv"
    "workspace"
    "*.log"
    "*.jsonl"
    "debug*"
    "check_errors*"
    "scratch"
    ".claude"
    ".amazonq"
    "audit_context.txt"
    "rust_context.txt"
    "*.token"
    "*.key"
    "*.pem"
    "*.p12"
    ".idea"
    ".vscode"
    "scripts/export_mimikri.sh"
)

# Construir flags de exclusión para rsync
EXCLUDE_FLAGS=""
for item in "${EXCLUDES[@]}"; do
    EXCLUDE_FLAGS="$EXCLUDE_FLAGS --exclude=$item"
done

# 3. Sincronizar archivos
echo "📦 Sincronizando archivos..."
rsync -avz $EXCLUDE_FLAGS "$SOURCE_DIR/" "$DEST_DIR/"

# 4. Renombrar referencias internas (Rebranding a mimikri)
echo "🔧 Renombrando referencias a 'mimikri'..."
cd "$DEST_DIR"

# Renombrar directorio redteam_rust_core -> mimikri_core
if [ -d "redteam_rust_core" ]; then
    mv redteam_rust_core mimikri_core
fi

# Reemplazar cadenas SOLO en archivos de texto (Whitelist de extensiones)
# Esto previene la corrupción de binarios (hallazgo #2)
TEXT_EXTS="\.rs$|\.toml$|\.yml$|\.yaml$|\.md$|\.sh$|\.txt$|\.service$|\.sql$|\.json$"
find . -type f | grep -E "$TEXT_EXTS" | xargs sed -i 's/osint-ultimate/mimikri/g' || true
find . -type f | grep -E "$TEXT_EXTS" | xargs sed -i 's/OsintUltimate/Mimikri/g' || true
find . -type f | grep -E "$TEXT_EXTS" | xargs sed -i 's/redteam_rust_core/mimikri_core/g' || true
find . -type f | grep -E "$TEXT_EXTS" | xargs sed -i 's/OSINT Ultimate/Mimikri/g' || true

# 5. Parchear hallazgos de seguridad y estructura
echo "🛡️ Aplicando parches de seguridad..."

# Parchear docker-compose.db.yml (Password de Postgres - hallazgo #2 original)
if [ -f "docker-compose.db.yml" ]; then
    sed -i 's/POSTGRES_PASSWORD: WENYANULTRA_SECURE_PASS/POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-}/g' docker-compose.db.yml
fi

# Crear estructura de workspace (hallazgo #5)
mkdir -p mimikri_core/workspace/{logs,reports,plugins}
touch mimikri_core/workspace/logs/.gitkeep

# Crear mimikri.service (Apuntando a .env y binario correcto - hallazgos #1 y #3)
cat << EOF > mimikri.service
[Unit]
Description=Mimikri Autonomous Red-Team Engine
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=osint
WorkingDirectory=/home/osint/mimikri/mimikri_core
EnvironmentFile=/home/osint/mimikri/.env
ExecStart=/home/osint/mimikri/mimikri_core/target/release/mimikri_core \\
    --dashboard 8080 \\
    --mcp-server \\
    --mcp-port 3001 \\
    --json-logs
Restart=always
RestartSec=10
TimeoutStopSec=15
NoNewPrivileges=yes
PrivateTmp=yes
LimitNOFILE=65535
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mimikri

[Install]
WantedBy=multi-user.target
EOF

# Eliminar archivo de servicio viejo
rm -f osint-ultimate.service

# 6. Crear .gitignore de producción endurecido
cat << EOF > .gitignore
# Mimikri Production Gitignore
target/
node_modules/
venv/
workspace/
!workspace/logs/.gitkeep
*.log
*.jsonl
.env
.env.*
!.env.example
*.token
*.key
*.pem
*.p12
.idea/
.vscode/
.claude/
.amazonq/
debug*
check_errors*
scratch/
DOCS/
audit_context.txt
rust_context.txt
EOF

# 7. Crear .dockerignore en el núcleo
cat << EOF > mimikri_core/.dockerignore
target/
node_modules/
venv/
workspace/
*.log
*.jsonl
.env
.env.*
!.env.example
*.token
*.key
*.pem
*.p12
.git/
.idea/
.vscode/
scratch/
DOCS/
EOF

# 8. Inicializar Git
echo "📂 Inicializando repositorio Git..."
git init
git checkout -b main
git add .
git commit -m "Initial commit for Mimikri (Sanitized & Hardened)"

echo ""
echo "✅ ¡Exportación completada con éxito!"
echo "Tu repositorio limpio está listo en: $DEST_DIR"
echo ""
echo "⚠️  NOTA DE SEGURIDAD: Verifica con 'git grep sk-' que no haya quedado ninguna API key filtrada antes de subir."
echo ""
echo "Próximos pasos:"
echo "1. Crea un nuevo repositorio en GitHub llamado 'mimikri'"
echo "2. Ejecuta: cd $DEST_DIR"
echo "3. Ejecuta: git remote add origin https://github.com/TU_USUARIO/mimikri.git"
echo "4. Ejecuta: git push -u origin main"
