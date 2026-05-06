# 06 - REST API reference

Base URL: `http://<host>/api`. All non-public routes require `Authorization: Bearer <jwt>`.

## Auth

- `POST /auth/login` - form-urlencoded `username` + `password`; returns `{ access_token, token_type, expires_in, user }`.
- `GET /auth/me` - returns current user info.

## Status

- `GET /health` - public liveness probe.
- `GET /status` - authenticated system metrics and detector readiness.
- `GET /stats` - authenticated severity breakdown and 24h counts.

## Agents

- `POST /agents/enroll` - open enrollment route; registers a new endpoint and returns a 30-day agent JWT.
- `POST /agents/heartbeat` - agent-authenticated last-seen and metrics update.
- `GET /agents` - authenticated agent listing.

In production, place `/agents/enroll` behind nginx and require the enrollment secret header.

## Threats

- `GET /threats?limit=100` - authenticated newest-first threat list.
- `POST /threats` - authenticated manual threat ingestion.
- `POST /threats/{id}/quarantine` - marks a threat as quarantined.
- `POST /threats/{id}/neutralize` - marks a threat as neutralized.
- `POST /threats/{id}/dismiss` - marks a threat as false positive.

## Scans

- `POST /scans` - starts an async scan with `scan_type` set to `quick`, `full` or `custom`.
- `GET /scans/{id}` - reads scan status.
- `POST /scans/{id}/cancel` - cancels a running scan.

## Analysis

- `POST /analyze/file` - authenticated file upload and analysis, limited by `MAX_UPLOAD_MB`.
- `POST /analyze/agent-file` - agent-authenticated file upload and analysis.

## Eradication

- `POST /eradications` - builds and executes an eradication plan.
- `GET /eradications` - reads eradication history.

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

## Network

- `GET /network/stats` - authenticated network telemetry summary.
- `GET /network/beacons` - authenticated beaconing candidates.
- `POST /network/dga` - authenticated DGA score for a domain.
- `POST /network/events` - authenticated network event ingestion.

## Chat assistant

- `POST /chat` - authenticated SOC assistant question, investigation summary or next actions.
- `GET /chat/faq` - public FAQ knowledge base.
- `GET /chat/suggestions` - public starter questions.
- `GET /chat/provider` - public assistant provider status.

The optional n8n workflow in [integrations/n8n/guardian-soc-alerting-workflow.json](../integrations/n8n/guardian-soc-alerting-workflow.json) posts a SOC digest to `/chat` so notifications include a GuardIAn analyst summary.

Example body:

```json
{
  "message": "Resume ce digest SOC et propose les prochaines actions defensives.",
  "language": "fr"
}
```

## External workflows

GuardIAn does not require n8n to run. External workflow automation is documented in [docs/10-WORKFLOWS-ALERTING.md](10-WORKFLOWS-ALERTING.md).

Current integration path:

- n8n reads GuardIAn via `/threats` and `/chat`.
- Nuclei results come from an allowlisted internal runner, not from GuardIAn itself.
- Native ingestion of external workflow events is a roadmap item, not a public API yet.

## Errors

All errors return `{ "detail": "<message>" }` with the appropriate HTTP code. `401` means the token expired or is invalid; the SPA logs the user out automatically.
