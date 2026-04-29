"""Pytest fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Use SQLite for tests
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("BOOTSTRAP_ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "TestPassword123!")

_tmp = Path(tempfile.gettempdir()) / "ransomguard_test"
_tmp.mkdir(exist_ok=True)
os.environ.setdefault("STORAGE_DIR", str(_tmp))
os.environ.setdefault("UPLOADS_DIR", str(_tmp / "uploads"))
os.environ.setdefault("QUARANTINE_DIR", str(_tmp / "quarantine"))
os.environ.setdefault("MODELS_DIR", str(_tmp / "models"))
os.environ.setdefault("RULES_DIR", str(_tmp / "rules"))
