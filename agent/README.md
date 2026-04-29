# RansomGuard Agent (Windows / Linux)

Lightweight Python agent that watches the file-system, performs cheap local
triage, and uploads suspicious files to the central RansomGuard API for
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
python -m ransomguard_agent --enroll        # registers with the backend, saves token
python -m ransomguard_agent                 # starts the watcher loop
```

## Build a single-file `.exe` (Windows)

```powershell
pip install .[build]
pyinstaller --onefile --name ransomguard-agent ransomguard_agent\__main__.py
```

The binary is produced in `dist\ransomguard-agent.exe`.

## Run as a Windows Service

Use NSSM (https://nssm.cc) or `sc.exe`:

```powershell
nssm install RansomGuardAgent "C:\Program Files\RansomGuard\ransomguard-agent.exe"
nssm set    RansomGuardAgent AppDirectory "C:\Program Files\RansomGuard"
nssm start  RansomGuardAgent
```

## Threat model

- The agent token is bound to the host (30-day TTL, rotatable).
- Uploads are **never** automatic execution — the backend just analyzes
  the bytes and stores a `Threat` record if positive.
- Quarantine / kill actions on the endpoint are explicit jobs pushed
  back from the backend (future work — see `docs/05-AGENT-WINDOWS.md`).
