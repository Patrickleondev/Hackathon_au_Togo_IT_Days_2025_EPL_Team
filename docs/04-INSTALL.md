# 04 — Installation

## Prerequisites

- Docker Engine ≥ 24 + Docker Compose v2
- 2 vCPU / 4 GB RAM minimum (8 GB recommended)
- 20 GB free disk

## Quick start (development)

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team

cp infra/.env.example infra/.env
# Edit infra/.env — set SECRET_KEY (openssl rand -hex 32) and admin password

docker compose -f infra/docker-compose.yml up --build
```

Then open:

- Frontend: <http://localhost:5173>
- API docs: <http://localhost:8000/docs>
- API health: <http://localhost:8000/api/health>

Default admin credentials are loaded from `BOOTSTRAP_ADMIN_EMAIL` /
`BOOTSTRAP_ADMIN_PASSWORD` on first run.

## Train the detector (first time)

```bash
docker compose -f infra/docker-compose.yml exec backend \
    python -m scripts.train_detector
```

The model is written to `/var/lib/guardian/models/detector.joblib` inside
the `rg_data` volume.

## Production deployment

See [08-DEPLOYMENT.md](08-DEPLOYMENT.md). In short:

```bash
cp infra/.env.example infra/.env       # set strong secrets
docker compose -f infra/docker-compose.prod.yml up -d --build
```

Then put real TLS certs in `infra/nginx/certs/` and uncomment the HTTPS block
in `infra/nginx/default.conf`.

## Manual (no Docker) backend setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .[dev]
export DATABASE_URL=sqlite:///./dev.db   # or your PostgreSQL URL
uvicorn app.main:app --reload
```
