.PHONY: help dev prod down logs build train test fmt lint clean

help:
	@echo "GuardIAn — make targets"
	@echo "  make dev         Start full stack (backend + worker + frontend + db + redis) with hot-reload"
	@echo "  make prod        Start production stack (nginx + TLS + tuned containers)"
	@echo "  make down        Stop and remove containers"
	@echo "  make logs        Tail all container logs"
	@echo "  make build       Rebuild all images"
	@echo "  make train       Train ML detector (writes backend/app/ml/models/)"
	@echo "  make test        Run backend pytest suite"
	@echo "  make fmt         Format Python (ruff) and TS (prettier)"
	@echo "  make lint        Lint Python (ruff) and TS (eslint)"
	@echo "  make clean       Remove __pycache__ / dist / node_modules"

dev:
	docker compose -f infra/docker-compose.yml up --build

prod:
	docker compose -f infra/docker-compose.prod.yml up -d --build

down:
	docker compose -f infra/docker-compose.yml down -v
	docker compose -f infra/docker-compose.prod.yml down -v 2>/dev/null || true

logs:
	docker compose -f infra/docker-compose.yml logs -f --tail=100

build:
	docker compose -f infra/docker-compose.yml build

train:
	cd backend && python scripts/train_detector.py

test:
	cd backend && pytest -q

fmt:
	cd backend && ruff format .
	cd frontend && npm run format || true

lint:
	cd backend && ruff check .
	cd frontend && npm run lint

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/node_modules frontend/dist agent/dist agent/build
