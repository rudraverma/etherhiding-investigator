# EtherHawk — Deployment Notes
*CyberHawk Threat Intel | Rudra Verma | 2026-10-26*

## Deployment target

**Server:** cyberhawk-server-ubuntu (`10.100.20.3`)
**Compose dir:** `/home/cyberhawk/docker/compose-files/etherhiding-investigator/`
**Local mirror:** `D:\Claude-Code\cyberhawk-server\etherhiding-investigator\`

## Services & ports

| Service | Container | Host port | Notes |
|---|---|---|---|
| Dashboard UI | `etherhawk-ui` | **8103** | CyberHawk-branded React SPA |
| Orchestrator API | `etherhawk-api` | **127.0.0.1:8104** | Localhost only — proxied by nginx |
| MITM proxy | `etherhawk-proxy` | — (internal) | Proxy on :8095, mitmweb on :8081 (internal) |
| Browser worker | `etherhawk-browser` | — (internal) | Headful Chromium via Xvfb, no direct internet |
| Deobfuscator | `etherhawk-deobf` | — (internal) | JS/PS beautify + IOC extract on :3020 |
| JS sandbox | `etherhawk-sandbox` | — (internal) | No-egress, cap_drop ALL, read_only |

Ports 8103/8104 chosen to avoid conflicts with existing services:
- 8080 → phishing-re-analyzer
- 8094 → ch-ether-api (old EtherHawk webhook receiver)
- 8095-8097 → ch-ether-proxy

## Secrets (all in KeyVault)

**Vault:** `etherhiding-investigator` (ID: `51d9e4df-c013-468c-b615-40cc71672c62`)

| Secret name | KV ID | Purpose |
|---|---|---|
| `ETHERHAWK_DASHBOARD_TOKEN` | `affd2a0c-4c7a-4e5b-b6d5-edd9d1fc81fa` | Dashboard login token |
| `MISP_URL` | `cf22ec5b-94bb-4805-ae51-8842c5733a96` | MISP instance URL |
| `MISP_API_KEY` | `c3e21ff1-5139-47c1-84ef-3ce382f04d5d` | MISP API key |

The `.env` on the server is ephemeral/derived — regenerate from KeyVault if lost.
**Never commit `.env`.**

## Manage

```bash
# Start all services
cd /home/cyberhawk/docker/compose-files/etherhiding-investigator
docker compose up -d

# View logs
docker compose logs -f --tail=50

# Restart a single service
docker compose restart etherhawk-api

# Rebuild after code change
docker compose build etherhawk-api
docker compose up -d --no-deps etherhawk-api

# Stop everything
docker compose down
```

## Access

Dashboard: **http://10.100.20.3:8103**
Login with `ETHERHAWK_DASHBOARD_TOKEN` from KeyVault.

Complete MISP configuration from the **Settings** tab in the dashboard
(pre-filled from .env — just verify and save).

## Sync reminder

After any server-side code change, sync back to local:
```bash
rsync -av /home/cyberhawk/docker/compose-files/etherhiding-investigator/ \
  /mnt/rudra-pc/cyberhawk-server/etherhiding-investigator/
```
