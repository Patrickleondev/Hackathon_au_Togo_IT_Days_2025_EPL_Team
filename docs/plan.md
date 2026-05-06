# Plan d'evolution GuardIAn

Ce document conserve la feuille de route technique issue de l'audit du projet.
Il ne doit pas contenir de liens locaux VS Code ou de traces de session.

## Lacunes identifiees

### Analyse statique

- Fuzzy hashing encore limite : ssdeep, TLSH et imphash doivent etre renforces.
- Parsing PE profond a completer : sections, imports suspects, Authenticode, Rich header.
- Detection de packers a etendre : UPX, Themida, VMProtect.
- Capacites type FLARE capa a integrer dans le tagging ATT&CK.
- Regles YARA encore limitees a [backend/app/ml/rules/generic.yar](../backend/app/ml/rules/generic.yar).

### Analyse comportementale

- Correlation parent-enfant encore limitee.
- Mapping MITRE ATT&CK a enrichir.
- Ingestion ETW/Sysmon cote Windows a formaliser.
- Canary files pour ransomware a ajouter.
- Scan memoire agent-side a etudier.

### Reseau

- Fingerprinting JA3/JA3S/JA4 a completer.
- Detection DGA a ameliorer et valider sur jeux de donnees.
- Detection beaconing a exploiter dans la console SOC.
- Ingestion Suricata/Zeek a documenter et tester.
- Matching threat-intel live sur IP/domaines a etendre.

### Threat intelligence

- Pipeline abuse.ch a maintenir : MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker, YARAify.
- AbuseIPDB et AlienVault OTX restent optionnels selon les cles disponibles.
- Scheduler de rafraichissement et audit de feed a surveiller.

### ML

| Modele | Role | Pourquoi |
| --- | --- | --- |
| EMBER + LightGBM | PE statique | baseline robuste et rapide |
| MalConv2 | bytes PE bruts | resistance partielle a l'obfuscation |
| CANINE-c | scripts obfusques | char-level sans tokenizer fragile |
| CodeBERT / UniXcoder | scripts malveillants | comprehension semantique |
| LSTM/TCN char-level | DGA | inference rapide |
| Isolation Forest / Deep SVDD | telemetry anomaly | detection sans label |
| Meta-learner empile | fusion finale | reduire l'evasion mono-modele |

## Plan en sept phases

### A. Threat-intelligence service

- Feeds abuse.ch : MalwareBazaar, URLhaus, ThreatFox, Feodo, YARAify.
- Tables `intel_hashes`, `intel_indicators`, `intel_yara_rules`, `intel_feed_runs`.
- Scheduler APScheduler toutes les 6 heures.
- Endpoints `/api/intel/stats`, lookup hash et lookup indicator.

### B. Static-V2

- Multi-hash : SHA-256, ssdeep, TLSH, imphash.
- Parsing PE approfondi avec `pefile`.
- Heuristiques packers et imports suspects.
- Tags ATT&CK derives de capacites.

### C. Network-V2

- Ingestion evenements reseau via `/api/network/events`.
- DGA scoring via `/api/network/dga`.
- Beaconing via `/api/network/beacons`.
- Stats SOC via `/api/network/stats`.

### D. Behavioral / APT engine

- Ingestion Sysmon/ETW.
- Correlation process-tree.
- Sigma-rule engine.
- Canary files ransomware.
- Mapping ATT&CK technique vers score.

### E. ML-V2

- LightGBM / ONNX Runtime cote backend.
- Entrainement lourd hors production, par exemple Colab.
- Export de modeles signes.
- Meta-score unifie exploitable par le SOC.

### F. MLOps

- Active learning depuis les cas low-confidence.
- Detection de drift.
- Registry de modeles.
- Deploiement canary par groupe d'agents.

### G. Workflow SOC et alerting continu

- n8n optionnel pour orchestrer les digests SOC et les escalades.
- Runner Nuclei interne, allowliste, limite et desactive par defaut.
- Notifications Discord, Telegram, WhatsApp provider webhook.
- Resume analyste via `/api/chat` avant envoi aux canaux d'astreinte.
- Future ingestion native `/api/workflows/events` pour historiser les resultats externes.

## Decisions validees

- Priorite initiale : Phase A puis Network-V2 et Static-V2.
- LLM du chatbot optionnel : garder `LLM_PROVIDER=none` si aucune cle officielle n'est configuree.
- Dependances ML lourdes : entrainement hors backend, inference CPU legere en production.
- Workflows externes : rester optionnels et ne jamais lancer de scan hors perimetre autorise.
