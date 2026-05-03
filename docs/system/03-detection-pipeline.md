# 03 - Detection pipeline

This page follows a suspicious file from endpoint observation to SOC verdict.
It complements the API reference in [../06-API.md](../06-API.md).

## 1. Capture

An endpoint agent watches high-risk locations such as downloads, temporary
folders and user workspaces. When a risky file appears, the agent computes a
local SHA-256 hash and applies lightweight heuristics before uploading.

| Step | Actor | Result |
| --- | --- | --- |
| File event | Agent watcher | new or modified file detected |
| Hashing | Agent | SHA-256 computed locally |
| Local triage | Agent | obviously safe files can be ignored |
| Upload | Agent | `POST /api/analyze/agent-file` |

Analysts can also upload a file manually from the SOC console through
`POST /api/analyze/file`.

## 2. Backend reception

```python
# backend/app/api/routers/analyze.py
@router.post("/analyze/file")
async def analyze_file(file: UploadFile):
    data = await file.read()
    result = get_detector().analyze_bytes(file.filename, data)
    return result.to_dict()
```

The agent route follows the same detector path, but requires an agent JWT.

## 3. Detector layers

The unified detector combines several signals instead of trusting one model
blindly.

| Layer | Signal | Purpose |
| --- | --- | --- |
| Exact hash intel | SHA-256 lookup | known malware or known clean match |
| Static PE parsing | imports, sections, entropy | ransomware-like structure |
| Heuristics | entropy, extensions, suspicious names | fast first-pass scoring |
| YARA | local rules | signature and family hints |
| ML model | trained feature vector | probabilistic score |
| Network context | DGA, JA3, beaconing when available | campaign-level correlation |

## 4. Verdict

The detector returns a normalized result:

```json
{
  "is_threat": true,
  "severity": "high",
  "confidence": 0.91,
  "threat_type": "ransomware",
  "description": "Suspicious encrypted payload with high entropy",
  "indicators": {}
}
```

If `is_threat=true`, the backend persists a threat record and makes it visible
in the SOC console.

## 5. SOC actions

| Action | Endpoint | Effect |
| --- | --- | --- |
| Quarantine | `POST /api/threats/{id}/quarantine` | mark and isolate evidence |
| Neutralize | `POST /api/threats/{id}/neutralize` | mark as handled |
| Dismiss | `POST /api/threats/{id}/dismiss` | false positive workflow |
| Scan | `POST /api/scans` | start quick/full/custom scan |

The UI keeps these actions explicit so an analyst can review before changing a
threat status.

## 6. Degraded modes

| Condition | Behaviour |
| --- | --- |
| ML model unavailable | heuristic/YARA fallback, `detector_ready=false` |
| Threat intel keys missing | optional feeds disabled or empty |
| Network telemetry absent | file pipeline still works |
| Worker unavailable | async scans pause until worker returns |

## 7. Validation commands

```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/docs
```

Manual file analysis from a shell requires an analyst token:

```bash
curl -X POST http://localhost:8000/api/analyze/file \
  -H "Authorization: Bearer <token>" \
  -F "file=@sample.bin"
```
