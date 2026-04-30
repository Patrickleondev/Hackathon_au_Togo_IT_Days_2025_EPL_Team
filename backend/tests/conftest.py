"""Pytest fixtures.

Test-only environment values are generated at runtime (never hardcoded) so
that secret-scanners cannot mistake fixtures for real credentials.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

# Use SQLite for tests
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("APP_ENV", "test")
# Generate ephemeral, per-process values. These never appear in source.
os.environ.setdefault("SECRET_KEY", secrets.token_hex(32))
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", secrets.token_urlsafe(24))

_tmp = Path(tempfile.gettempdir()) / "guardian_test"
_tmp.mkdir(exist_ok=True)
os.environ.setdefault("STORAGE_DIR", str(_tmp))
os.environ.setdefault("UPLOADS_DIR", str(_tmp / "uploads"))
os.environ.setdefault("QUARANTINE_DIR", str(_tmp / "quarantine"))
os.environ.setdefault("MODELS_DIR", str(_tmp / "models"))
os.environ.setdefault("RULES_DIR", str(_tmp / "rules"))
