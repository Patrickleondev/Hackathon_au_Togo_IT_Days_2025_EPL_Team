import asyncio
import json
import os
import sys
import tempfile

# S'assurer que le dossier parent (backend) est dans le path
CURRENT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from httpx import AsyncClient, ASGITransport  # type: ignore
import main  # importe l'application FastAPI existante


async def test_eradication_dry_run():
    # Créer un dossier temporaire avec quelques fichiers
    with tempfile.TemporaryDirectory() as tmpdir:
        for i in range(3):
            with open(os.path.join(tmpdir, f"file_{i}.txt"), "w", encoding="utf-8") as f:
                f.write("sample content")

        payload = {
            "alert_id": "ALRT-TEST-0001",
            "scope": {"hosts": ["localhost"], "paths": [tmpdir]},
            "actions": ["kill_processes", "quarantine_files"],
            "dry_run": True,
            "min_confidence": 0.0,
        }

        async with AsyncClient(transport=ASGITransport(app=main.app), base_url="http://test") as client:
            resp = await client.post("/api/eradications", json=payload)
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data.get("dry_run") is True
            assert isinstance(data.get("steps"), list) and len(data["steps"]) >= 1
            step = data["steps"][0]
            assert step.get("preview") is True
            assert step.get("path") == tmpdir
            # Stats cohérentes
            stats = data.get("stats", {})
            assert "files_evaluated" in stats


async def main_async():
    await test_eradication_dry_run()


if __name__ == "__main__":
    asyncio.run(main_async())