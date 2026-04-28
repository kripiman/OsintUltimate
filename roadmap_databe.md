# 🗺️ OsintUltimate Cloud Roadmap

## 🟩 Fase 1: Cimentación (Completado)

- [X] Lanzamiento de Instancia Oracle (Ampere A1 - 4 cores / 24GB RAM).
- [X] Configuración de Red Mimikri (Public/Private Subnets).
- [X] Entorno de Compilación (Rust, Go, Node.js).
- [X] Herramienta de Agente (Claude Code instalado).

## 🟨 Fase 2: Inteligencia Local (Ahora)

- [ ] **Instalar Ollama:** Para tener un LLM local tipo Llama 3 o Mistral.
- [ ] **Descargar Modelos:** `ollama run llama3:8b` (Aprovechando los 24GB de RAM).
- [ ] **Configuración de Variables:** Configurar `.env` para que el Rust Core detecte a Ollama.

## 🟧 Fase 3: Persistencia y Datos (Para más tarde)

- [ ] **Instalación de PostgreSQL:** Base de datos robusta para findings.
- [ ] **Configuración de Seguridad:** Hardening de puertos y Firewall (iptables).
- [ ] **Docker Engine:** Para contenedores de herramientas legacy.

## 🟥 Fase 4: Operaciones (Misiones)

- [ ] **Sincronización de Código:** Subir `OsintUltimate` y compilar.
- [ ] **Digital Ocean Swarm:** Conectar la API de DO para lanzar nodos.
- [ ] **Primer Escaneo:** Prueba de orquestación HQ -> Nodos.
