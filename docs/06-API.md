# 06 — REST API reference

Base URL: `http://<host>/api`. All non-public routes require
`Authorization: Bearer <jwt>`.

## Auth

| Method | Path | Body | Notes |
|--------|------|------|-------|
| POST | `/auth/login` | `username` + `password` (form-urlencoded, OAuth2) | Returns `{ access_token, token_type, expires_in, user }` |
| GET | `/auth/me` | — | Current user info |

## Status

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness probe |
| GET | `/status` | user | System metrics + detector readiness |
| GET | `/stats` | user | Severity breakdown + 24h counts |

## Agents

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/agents/enroll` | open* | Register a new endpoint, returns 30-day agent JWT |
| POST | `/agents/heartbeat` | agent | Update last-seen + metrics |
| GET | `/agents` | user | List enrolled agents |

\* In production, place this behind nginx + an enrollment secret header.

## Threats

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/threats?limit=100` | user | List threats (newest first) |
| POST | `/threats` | user | Manual ingestion |
| POST | `/threats/{id}/quarantine` | user | Mark as quarantined |
| POST | `/threats/{id}/neutralize` | user | Mark as neutralized |
| POST | `/threats/{id}/dismiss` | user | False-positive |

## Scans

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/scans` | user | Start async scan (`scan_type`: quick/full/custom) |
| GET | `/scans/{id}` | user | Scan status |
| POST | `/scans/{id}/cancel` | user | Cancel a running scan |

## Analysis

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/analyze/file` | user | Upload + analyze a file (max `MAX_UPLOAD_MB`) |
| POST | `/analyze/agent-file` | agent | Same, called by endpoint sensors |

## Eradication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/eradications` | user | Build & execute an eradication plan |
| GET | `/eradications` | user | History |

Example body:

```json
{
  "threat_id": "abc...",
  "actions": ["quarantine_files", "kill_processes"],
  "scope": {
    "paths": ["/var/lib/guardian/uploads/foo.exe"],
    "agent_ids": [],
    "process_names": []
  },
  "min_confidence": 0.85,
  "dry_run": true
}
```

## Errors

All errors return `{ "detail": "<message>" }` with the appropriate HTTP code.
401 means token expired or invalid; the SPA logs the user out automatically.
