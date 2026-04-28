# AUDIT 2026-04-28 | 750f1a1e

PROD_READY: 62%

ORACLE: WARN — Memory defaults SOFT=600/HARD=900MB vs 24GB target. Raise: SOFT=16000,HARD=20000. Concurrency=10→50. MAX_TOKENS=4096→500000. MemoryMonitor logs-only on HARD breach; add process::exit.

DO_SCANNERS: WARN — ssh_keys=[] in CreateDropletRequest; no node access if danted fails. Hysteria binary unpinned (supply chain). Fail-closed OK. Auto-destroy 120m OK.

MISSING_ENV: DIGITALOCEAN_TOKEN, SOFT_MEMORY_LIMIT, HARD_MEMORY_LIMIT, DEFAULT_CONCURRENCY, MAX_TOKENS, PROXY_MODE, PROXY_POOL_SIZE, CHAOS_API_KEY, NETLAS_API_KEY, SECURITYTRAILS_API_KEY, SHODAN_API_KEY, CRIMINALIP_API_KEY, CAIDO_API_KEY, MCP_TOKEN, DISCORD_WEBHOOK_URL, OLLAMA_URL

MISSING: DB schema (persistence.rs exists, no migrations), AUDIT_REPORT.md, skills/OSINT_STRATEGY

NEXT:
1. DO_SSH_KEY_ID → ssh_keys field
2. .env.oracle prod values
3. DB migration files
4. Pin Hysteria hash
5. SIGTERM on HARD mem breach
6. Oracle ARM systemd service

STATS: 982 tokens saved | V15.1.0 Sovereign