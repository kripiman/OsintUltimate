## ESTADO ACTUAL — 2026-04-28 (sesión 4d4b9721 → 750f1a1e)
FASE: PRODUCCIÓN LISTA
PROD_READY: 95%

COMPLETADO:
- PostgreSQL: sink.rs, cve_cache.rs, deduplication.rs, mcp/server.rs → sqlx::PgPool + $1/$2 + ON CONFLICT
- DB Schema: migrations/20260428000000_initial_pg_schema.sql (9 tablas: scans, targets, findings, objectives, agent_sessions, plugin_cache, mcp_stats, checkpoints, deduplication, cve_cache)
- memory_monitor.rs: std::process::exit(1) en HARD breach. systemd Restart=always maneja rearme.
- digital_ocean.rs: DO_SSH_KEY_ID desde env, Hysteria v2.5.2 SHA-256 pinned
- .env.oracle: SOFT=16000, HARD=20000, CONCURRENCY=50, MAX_TOKENS=500000
- docker-compose.db.yml: postgres:16-alpine, 4GB limit, shared_buffers=1GB
- osint-ultimate.service: EnvironmentFile=.env.oracle, Restart=always, After=docker.service
- cargo check: 0 errores

PENDIENTE PARA GO-LIVE:
- Rellenar .env.oracle con tokens reales (DIGITALOCEAN_TOKEN, DO_SSH_KEY_ID, APIs)
- Cambiar password default WENYANULTRA_SECURE_PASS en docker-compose.db.yml
- Transferir repo a Oracle ARM VPS
- `docker compose -f docker-compose.db.yml up -d`
- `sqlx migrate run` (o DATABASE_URL set + cargo build --release)
- `sudo systemctl enable --now osint-ultimate`