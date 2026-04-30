# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps for psycopg + yara + Static-V2 (libfuzzy for ssdeep, libtlsh for tlsh)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libyara-dev \
        libmagic1 \
        libfuzzy-dev \
        libtlsh-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- deps layer ----
COPY pyproject.toml ./
RUN pip install --upgrade pip \
    && pip install --no-cache-dir \
        "fastapi==0.115.6" \
        "uvicorn[standard]==0.32.1" \
        "pydantic==2.9.2" \
        "pydantic-settings==2.6.1" \
        "sqlalchemy==2.0.36" \
        "alembic==1.14.0" \
        "psycopg[binary]==3.2.3" \
        "asyncpg==0.30.0" \
        "redis==5.2.1" \
        "rq==2.1.0" \
        "scikit-learn==1.5.2" \
        "numpy==2.1.3" \
        "joblib==1.4.2" \
        "passlib[bcrypt]==1.7.4" \
        "python-jose[cryptography]==3.3.0" \
        "python-multipart==0.0.20" \
        "structlog==24.4.0" \
        "psutil==6.1.0" \
        "email-validator==2.2.0" \
        "yara-python==4.5.1" \
        "httpx==0.28.1" \
        "apscheduler==3.10.4" \
        "tenacity==9.0.0" \
        "python-dateutil==2.9.0.post0" \
        "pefile==2024.8.26" \
        "python-tlsh==4.5.0" \
        "ssdeep==3.4"

# ---- app code ----
COPY app ./app
COPY scripts ./scripts

# Non-root user
RUN useradd --create-home --uid 1000 guardian \
    && mkdir -p /var/lib/guardian /var/lib/guardian/uploads \
                /var/lib/guardian/quarantine /var/lib/guardian/models \
                /var/lib/guardian/rules \
    && cp -r app/ml/rules/* /var/lib/guardian/rules/ 2>/dev/null || true \
    && chown -R guardian:guardian /app /var/lib/guardian

USER guardian

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
