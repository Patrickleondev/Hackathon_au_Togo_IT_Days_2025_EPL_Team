# 08 — Production deployment

## 1. Provision the host

- Linux server (Ubuntu 22.04 LTS recommended), 2 vCPU / 4 GB / 40 GB minimum.
- DNS A record pointing to the host (e.g. `soc.example.tg`).
- Open ports 80 and 443 inbound; 22 from your IP only.

## 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

## 3. Clone & configure

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team

cp infra/.env.example infra/.env
# Generate secrets:
echo "SECRET_KEY=$(openssl rand -hex 32)" >> infra/.env
echo "POSTGRES_PASSWORD=$(openssl rand -base64 24)" >> infra/.env
# Set bootstrap admin:
nano infra/.env   # set BOOTSTRAP_ADMIN_EMAIL / BOOTSTRAP_ADMIN_PASSWORD / CORS_ORIGINS
```

## 4. TLS certificates

```bash
mkdir -p infra/nginx/certs
# Either: copy real certs (Let's Encrypt)
sudo cp /etc/letsencrypt/live/soc.example.tg/fullchain.pem infra/nginx/certs/
sudo cp /etc/letsencrypt/live/soc.example.tg/privkey.pem   infra/nginx/certs/
sudo chown -R $USER infra/nginx/certs
# Or: self-signed for testing
openssl req -x509 -newkey rsa:4096 -keyout infra/nginx/certs/privkey.pem \
    -out infra/nginx/certs/fullchain.pem -days 365 -nodes -subj "/CN=soc.local"
```

Then uncomment the HTTPS block in `infra/nginx/default.conf`.

## 5. Build & start

```bash
docker compose -f infra/docker-compose.prod.yml up -d --build
```

Wait for `docker compose ps` to show all services as `healthy`.

## 6. First-run training

```bash
docker compose -f infra/docker-compose.prod.yml exec backend \
    python -m scripts.train_detector
```

## 7. Smoke test

```bash
curl https://soc.example.tg/api/health
```

Then login at <https://soc.example.tg> with the bootstrap credentials.

## Hardening checklist

- [ ] Change `BOOTSTRAP_ADMIN_PASSWORD` after first login.
- [ ] Restrict `CORS_ORIGINS` to your real frontend domain.
- [ ] Put the Postgres port behind the internal Docker network only (default).
- [ ] Run a host firewall (`ufw allow 22, 80, 443`).
- [ ] Schedule daily `pg_dump` to off-host storage.
- [ ] Mount `/var/lib/ransomguard` on encrypted storage.
- [ ] Enable `fail2ban` for `/api/auth/login`.
- [ ] Subscribe to security advisories for FastAPI / SQLAlchemy / Pillow.

## Updates

```bash
git pull
docker compose -f infra/docker-compose.prod.yml build
docker compose -f infra/docker-compose.prod.yml up -d
```

The DB schema is applied via `Base.metadata.create_all` on startup. For
breaking schema changes, switch to Alembic migrations (see
`backend/app/db/migrations/`).
