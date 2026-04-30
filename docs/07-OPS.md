# 07 — Operations

## Logs

All services use **structlog** in JSON mode in production:

```bash
docker compose -f infra/docker-compose.prod.yml logs -f backend worker
```

Each line includes ISO-UTC `timestamp`, `event`, and any contextvars
(`agent_id`, `threat_id`, …).

## Backups

Postgres is the single source of truth. Back up the volume daily:

```bash
docker compose -f infra/docker-compose.prod.yml exec -T db \
    pg_dump -U $POSTGRES_USER $POSTGRES_DB | gzip > backup-$(date +%F).sql.gz
```

The `rg_data` volume contains uploads, quarantine and the trained model — back
it up separately if you keep large samples.

## Updating YARA rules

Drop new `.yar` files into `backend/app/ml/rules/` and rebuild:

```bash
docker compose -f infra/docker-compose.prod.yml build backend worker
docker compose -f infra/docker-compose.prod.yml up -d backend worker
```

Or hot-update by `docker cp`-ing them into the running container under
`/var/lib/guardian/rules/` and restarting the backend.

## Re-training

```bash
docker compose -f infra/docker-compose.prod.yml exec backend \
    python -m scripts.train_detector \
        --benign /var/lib/guardian/samples/benign \
        --malicious /var/lib/guardian/samples/malicious
```

The new model is loaded on the next backend restart, or by calling
`get_detector().load()` manually.

## Health endpoints

| Endpoint | What it tells you |
|----------|-------------------|
| `GET /api/health` | Backend process is alive |
| `GET /api/status` | DB connectivity + detector readiness + system metrics |
| `docker inspect --format='{{.State.Health.Status}}' guardian-backend` | Container health |

## Scaling

The architecture is intentionally horizontal-friendly:

- `backend`: stateless, scale by replicating + load-balancing in nginx.
- `worker`: scale by adding more replicas (RQ pulls jobs from the same
  Redis queue).
- `db`: managed PostgreSQL or a streaming replica.
- `redis`: switch to a managed Redis or a Sentinel set-up.

## Common incidents

| Symptom | Action |
|---------|--------|
| `detector_ready=false` on `/status` | Run `train_detector`; check `MODELS_DIR` is mounted writable |
| YARA scores always 0 | `apt-get install libyara-dev` in image; or rules dir empty |
| All uploads return 413 | Increase `MAX_UPLOAD_MB` AND `client_max_body_size` in nginx |
| Agents 401 after 30 days | Re-enroll: `guardian-agent.exe --enroll` |
