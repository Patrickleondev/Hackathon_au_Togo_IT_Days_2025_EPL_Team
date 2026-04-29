"""Smoke test for the FastAPI app — uses sqlite + TestClient."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_endpoint():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "healthy"


def test_login_and_status_flow():
    import os

    app = create_app()
    with TestClient(app) as client:
        r = client.post(
            "/api/auth/login",
            data={
                "username": os.environ["BOOTSTRAP_ADMIN_EMAIL"],
                "password": os.environ["BOOTSTRAP_ADMIN_PASSWORD"],
            },
        )
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]

        r = client.get("/api/status", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["version"]
