# 09 — Contributing

## Branching

- `main` — protected, deployable.
- `dev` — integration branch.
- `feat/<short-name>` — feature branches off `dev`.
- `fix/<short-name>` — bugfix branches off `dev`.

PRs target `dev`; release PRs `dev → main` are tagged.

## Local setup

```bash
make dev          # start the full stack with hot-reload
make test         # run pytest in the backend container
make lint         # ruff + eslint
make fmt          # ruff format + prettier
```

## Code standards

### Backend (Python)

- Python 3.11+, type hints everywhere.
- `ruff` (line length 100, py311 target).
- All routes: dependency-inject `db: Session = Depends(get_db)` rather than
  importing `SessionLocal()` directly.
- All ML scoring in pure functions (no I/O).
- Pydantic v2 schemas in `app/schemas/` — never reuse SQLAlchemy models in
  responses.
- Logs: `structlog.get_logger(__name__)`, never `print()`.

### Frontend (TypeScript)

- React 18, strict TS, function components + hooks.
- Tailwind for styling (no CSS modules).
- All API calls through `src/api/client.ts`.
- No `any` for known shapes — extend the typed clients.

### Agent

- Keep dependencies minimal (no scikit-learn / no YARA on endpoint).
- All HTTP through `httpx`; never bare `urllib`.
- `__main__.py` only contains glue — actual logic in modules.

## Commit messages

Conventional Commits:

```
feat(backend): add /eradications router
fix(detector): correct YARA fallback weight when ML missing
docs(install): document offline training
```

## Security disclosures

Do not open public issues for security flaws — email
`security@guardian.local` (placeholder). Provide:

- Affected version
- Reproduction steps
- Suggested fix if any

We commit to acknowledging within 48 hours.
