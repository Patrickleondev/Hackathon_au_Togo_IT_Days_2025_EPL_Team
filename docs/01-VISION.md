# 01 — Vision & threat model

## Problem

Ransomware is the #1 threat against organizations in West Africa. Most
SMBs and public services in Togo cannot afford commercial XDR licenses.
**GuardIAn** delivers a self-hostable, open-source detection and
response platform that runs on a single Linux server and protects an
entire fleet of Windows / Linux endpoints.

## Goals

- Detect ransomware activity within seconds of file modification.
- Provide an analyst console (SOC) with full audit trail.
- Operate in air-gapped or low-bandwidth networks (offline ML model).
- Be deployable on a $20/month VPS or on-prem mini-PC.

## Non-goals (v2)

- Endpoint kernel-level prevention (we're an EDR-lite, not an antivirus).
- Multi-tenancy at the database layer (single-org per deployment).
- Compliance certifications (PCI / ISO 27001) — out of scope for the hackathon.

## Threat model

Assumed adversaries:

| Actor | Capability | What we defend |
|-------|------------|----------------|
| Commodity ransomware (Phobos, Stop/Djvu, …) | Drops payload in `%APPDATA%`, runs `vssadmin delete shadows`, encrypts files in user dirs | Heuristic + YARA + ML on dropped binary, ransom-note detection |
| Malicious macro / loader | Office doc downloads payload | YARA `Suspicious_PowerShell_Obfuscation` + `downloader` patterns |
| Insider exfiltration | Copies sensitive files to `.zip` and uploads | Out of scope (use DLP) |
| Targeted APT with kernel exploits | Disables agent | Acknowledged limit — see "Defense in depth" |

## Architecture overview

```
┌──────────────────────┐         ┌────────────────────────────┐
│  Windows endpoints   │ HTTPS+  │   GuardIAn Backend      │
│  guardian-agent   │ JWT     │   FastAPI + Worker         │
│  (watchdog + httpx)  │ ───────►│   PostgreSQL + Redis       │
└──────────────────────┘         │   Unified detector         │
                                 │   (Heuristic+ML+YARA)      │
┌──────────────────────┐         │                            │
│  Analyst browser     │ HTTPS   │   Reverse proxy nginx       │
│  React/Vite SPA      │ ───────►│                            │
└──────────────────────┘         └────────────────────────────┘
```

See [02-ARCHITECTURE.md](02-ARCHITECTURE.md) for sequence diagrams and the
data model.
