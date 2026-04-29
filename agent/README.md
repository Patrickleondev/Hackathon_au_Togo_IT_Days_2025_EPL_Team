# GuardIAn Agent (Windows / Linux)

Lightweight Python agent that watches the file-system, performs cheap local
triage, and uploads suspicious files to the central GuardIAn API for
deep analysis.

## Install (developer mode)

```powershell
cd agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

## Configuration

The agent is configured via env vars (prefix `RG_`) or a local `.env`:

```env
RG_BACKEND_URL=http://soc.example.com
RG_API_PREFIX=/api
RG_WATCH_PATHS=["C:\\Users","D:\\Shares"]
RG_HEARTBEAT_SEC=30
RG_UPLOAD_MAX_MB=50
```

## First run

```powershell
python -m guardian_agent --enroll        # registers with the backend, saves token
python -m guardian_agent                 # starts the watcher loop
```

## Build a single-file `.exe` (Windows)

```powershell
pip install .[build]
pyinstaller --onefile --name guardian-agent guardian_agent\__main__.py
```

The binary is produced in `dist\guardian-agent.exe`.

## Run as a Windows Service

Use NSSM (https://nssm.cc) or `sc.exe`:

```powershell
nssm install GuardIAnAgent "C:\Program Files\GuardIAn\guardian-agent.exe"
nssm set    GuardIAnAgent AppDirectory "C:\Program Files\GuardIAn"
nssm start  GuardIAnAgent
```

## Threat model

- The agent token is bound to the host (30-day TTL, rotatable).
- Uploads are **never** automatic execution — the backend just analyzes
  the bytes and stores a `Threat` record if positive.
- Quarantine / kill actions on the endpoint are explicit jobs pushed
  back from the backend (future work — see `docs/05-AGENT-WINDOWS.md`).
