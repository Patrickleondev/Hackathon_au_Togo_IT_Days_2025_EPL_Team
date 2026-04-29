# 05 — Windows endpoint agent

The agent is a Python service that watches user / data directories, performs
cheap local triage and uploads only suspicious files to the central API for
authoritative analysis.

## Build a single-file `.exe`

On a Windows build machine:

```powershell
cd agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[build]
pyinstaller --onefile --name guardian-agent guardian_agent\__main__.py
```

The binary is produced in `agent\dist\guardian-agent.exe`.

## Deploy on a workstation

1. Copy `guardian-agent.exe` to `C:\Program Files\GuardIAn\`.
2. Create `C:\Program Files\GuardIAn\.env`:

   ```env
   RG_BACKEND_URL=https://soc.example.com
   RG_API_PREFIX=/api
   RG_WATCH_PATHS=["C:\\Users","D:\\Shares"]
   RG_HEARTBEAT_SEC=30
   RG_UPLOAD_MAX_MB=50
   ```

3. Enroll the agent:

   ```powershell
   cd "C:\Program Files\GuardIAn"
   .\guardian-agent.exe --enroll
   ```

   This writes the JWT token to `%USERPROFILE%\.guardian-agent\state.json`.

4. Install as a Windows service (NSSM):

   ```powershell
   nssm install GuardIAnAgent "C:\Program Files\GuardIAn\guardian-agent.exe"
   nssm set    GuardIAnAgent AppDirectory "C:\Program Files\GuardIAn"
   nssm set    GuardIAnAgent ObjectName LocalSystem
   nssm start  GuardIAnAgent
   ```

## What the agent does

| Phase | Implementation | File |
|-------|----------------|------|
| Watch FS | `watchdog.Observer` recursive on each path | `watcher.py` |
| Local triage | extension table + pattern regex + entropy | `heuristics.py` |
| Upload | `httpx` POST `/api/analyze/agent-file` | `client.py` |
| Heartbeat | every 30 s, posts CPU/RAM/uptime | `__main__.py` |

The local heuristic intentionally **errs on the side of uploading** — the
authoritative decision is taken by the central detector.

## Hardening

- Run the service as `LocalSystem` so it can read all user folders.
- Restrict outbound traffic to the SOC backend only (firewall rule).
- Rotate the agent token every 30 days (rebuild + re-enroll script).
