# 07 — Agent Windows

> L'agent est les *yeux* du système : il observe, collecte, soumet.

## Rôle

| Fonction | Détail |
| --- | --- |
| **Heartbeat** | Toutes les N secondes (défaut 30 s) — preuve de vie |
| **Real-time scanner** | Surveille `%TEMP%`, `Downloads`, `Desktop`, partages |
| **Telemetry** | Process tree, connexions réseau, modifs registre — **roadmap Phase D** |
| **File submission** | POST `/api/analyze/agent-file` quand un fichier suspect apparaît |
| **Eradication** | Quarantaine locale + suppression sur ordre du SOC |

## Architecture (cible Phase D)

```text
┌─────────────────────────────────────────────────┐
│  GuardIAn Tray Service (.NET 8 / C# OU PySide6) │
│   ┌────────────────────────────────────────┐    │
│   │ FileWatcher (ReadDirectoryChangesW)   │    │
│   ├────────────────────────────────────────┤    │
│   │ ETW / Sysmon Consumer (Phase D)       │    │
│   ├────────────────────────────────────────┤    │
│   │ Heartbeat scheduler (30s)             │    │
│   ├────────────────────────────────────────┤    │
│   │ HTTPS client (mutual-TLS optionnel)   │    │
│   └────────────────────────────────────────┘    │
└────────────────┬────────────────────────────────┘
                 │ POST /api/agents/heartbeat
                 │ POST /api/analyze/agent-file
                 │ GET  /api/eradication/orders
                 ▼
        ┌────────────────────┐
        │  Backend FastAPI   │
        └────────────────────┘
```text

## Authentification

JWT scope `agent` :

1. Provisioning : SOC génère un agent → token `scope=agent` long-lived
2. Token stocké dans `%PROGRAMDATA%\GuardIAn\agent.token` (ACL admin only)
3. Chaque requête : `Authorization: Bearer <token>`

## Flux d'une détection

```text
[fichier.exe créé dans Downloads]
        │
        ▼
[FileWatcher déclenche callback]
        │
        ▼
[Calcul SHA-256 local]
        │
        ▼
[POST /api/analyze/agent-file (multipart, ≤ 50 MB)]
        │
        ▼
[Reçoit DetectionResult]
        │
        ├── is_threat=False → log seul
        │
        └── is_threat=True
              │
              ▼
        [Quarantaine locale: déplace vers %PROGRAMDATA%\GuardIAn\Quarantine
         + chiffrement AES-256-GCM]
              │
              ▼
        [POST /api/threats (rapport)]
```

## Ordres d'éradication

L'agent poll `GET /api/eradication/orders?agent_id=...` toutes les 60 s. Le SOC peut :

- `delete` : supprime un fichier en quarantaine
- `restore` : déchiffre + restaure (faux positif)
- `isolate` : désactive l'interface réseau (Phase D)
- `kill_pid` : termine un processus (Phase D)

## Performance & impact système

| Métrique | Cible |
| --- | --- |
| RAM | < 100 Mo |
| CPU idle | < 0.5 % |
| CPU pic (analyse) | < 5 % |
| Latence file detect → submit | < 500 ms |

## Sécurité de l'agent

- Service Windows en `LocalSystem`, démarrage automatique
- Self-protection : protégé via `RPC_C_IMP_LEVEL_IDENTIFY` + ACL DACL deny-all aux non-admin
- Roadmap : signing Authenticode, anti-tampering via DSE/HVCI

## État actuel

Le code agent est dans `agent_windows/` (squelette PySide6). La Phase D (Sysmon/ETW + process tree) est priorité après la Phase C (réseau).

## Sources & lectures

- **Sysmon** : <https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon>
- **Sysmon-modular** (config baseline) : <https://github.com/olafhartong/sysmon-modular>
- **ETW** : <https://learn.microsoft.com/en-us/windows/win32/etw/>
- **MITRE ATT&CK D3FEND for endpoint** : <https://d3fend.mitre.org/>
- **Authenticode signing** : <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode>

## Suite

→ [08 — Installation pas à pas](08-installation-pas-a-pas.md)
