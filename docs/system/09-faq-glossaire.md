# 09 — FAQ & Glossaire

## FAQ

### Pourquoi 6 couches de détection ?

Aucune couche n'est parfaite. Un attaquant peut contourner UNE couche, plus difficilement TROIS, quasiment jamais SIX. C'est le principe de **défense en profondeur**.

### Mon antivirus existant détecte-t-il déjà tout ça ?

Non. Les antivirus grand-public (Defender, Kaspersky) excellent en signatures + heuristiques mais ne croisent pas avec les feeds TI live, n'utilisent pas ssdeep/tlsh à grande échelle, et les modèles ML sont fermés. GuardIAn est un **EDR open-source**, pas un AV de bureau.

### Combien de samples GuardIAn peut-il connaître ?

Avec 7 feeds rafraîchis toutes les 6 h et un cap de 250 k lignes par feed → ~1.5 M IOC actifs. La rétention coupe à 90 jours par défaut → typiquement ~500 k actifs.

### Faut-il un GPU ?

Pas pour l'inférence : LightGBM + ONNX Runtime tournent en CPU. Pour l'entraînement Phase E (MalConv2, CodeBERT), oui — utiliser Google Colab gratuit (T4) suffit.

### Comment minimiser les faux positifs ?

1. Toujours laisser tourner Phase A (TI exact) au moins 24 h pour peupler la DB
2. Ajuster `THRESHOLD_LOW/MEDIUM/HIGH` dans `infra/.env`
3. Enrôler des binaires légitimes signés Authenticode → exemption automatique (roadmap)
4. Phase F : active learning + drift detection corrigent les biais en continu

### GuardIAn peut-il bloquer un ransomware en cours d'exécution ?

Phase D (Sysmon + canary files) est dédiée à ça. Aujourd'hui (Phase A+B), GuardIAn détecte au stade **fichier déposé sur disque** mais ne hooke pas les API kernel — un dropper ransomware en mémoire passe sous le radar tant que le binaire n'est pas écrit.

### Les feeds TI sont-ils RGPD-compliant ?

Les IOC publics (hashes, IPs, domaines) ne sont pas des données personnelles. Les pulses OTX peuvent contenir des emails dans les indicateurs — ils sont stockés tels quels mais pas exposés en clair. À auditer avant production en UE.

### Comment GuardIAn protège ses propres clés ?

- `SECRET_KEY` jamais commit (env var) ; tests utilisent `secrets.token_hex(32)` runtime
- Tokens agent : storage `%PROGRAMDATA%\GuardIAn\` ACL admin only
- Roadmap : intégration HashiCorp Vault / Azure Key Vault

---

## Glossaire

### Sécurité

| Terme | Définition |
|-------|------------|
| **APT** (Advanced Persistent Threat) | Groupe attaquant sophistiqué et patient (souvent état-nation) |
| **C2** (Command & Control) | Serveur qui donne des ordres aux machines compromises |
| **DGA** (Domain Generation Algorithm) | Génère des milliers de domaines aléatoires pour le C2 |
| **DFIR** | Digital Forensics & Incident Response |
| **EDR** (Endpoint Detection & Response) | Plateforme de détection au niveau du poste |
| **IOC** (Indicator of Compromise) | Hash, IP, domaine, URL, etc. lié à une attaque |
| **LOLBin** (Living Off the Land Binary) | Binaire légitime de Windows abusé (powershell, certutil…) |
| **Sigma** | Format ouvert de règles de détection (alternative à YARA, mais sur logs) |
| **SOC** | Security Operations Center |
| **TI** (Threat Intelligence) | Renseignement sur les menaces, IOC + contexte |
| **TTPs** | Tactics, Techniques, Procedures (taxonomie MITRE ATT&CK) |
| **XDR** | Extended Detection & Response (EDR + réseau + cloud) |
| **YARA** | Langage de règles pour matcher des bytes/patterns dans des fichiers |
| **Zero-day** | Vulnérabilité ou malware inconnu publiquement |

### ML

| Terme | Définition |
|-------|------------|
| **Active learning** | Le modèle demande des labels sur les cas où il est incertain |
| **ADWIN** | ADaptive WINdowing — détecte un changement statistique en streaming |
| **CodeBERT** | LLM pré-entraîné sur du code |
| **EMBER** | Dataset PE statique avec ~10 M samples + features Endgame |
| **F1-score** | Moyenne harmonique précision/rappel — métrique classique |
| **FPR** (False Positive Rate) | Taux de faux positifs — critique pour antivirus (<1 %) |
| **LightGBM** | Boosting d'arbres très rapide (Microsoft) |
| **MalConv** | CNN sur bytes bruts d'un PE (Raff 2017) |
| **ONNX** | Open Neural Network Exchange — format portable |
| **Shadow mode** | Modèle déployé en parallèle sans agir sur la décision |
| **Stacking** | Combiner plusieurs modèles via un méta-modèle |

### Hashes

| Terme | Définition |
|-------|------------|
| **SHA-256** | Cryptographique. Change totalement avec 1 bit modifié |
| **imphash** | Hash de la table d'imports d'un PE (Mandiant 2014) |
| **ssdeep** | Fuzzy hash CTPH (Kornblum 2006) |
| **TLSH** | Locality-sensitive hash (Trend Micro 2013) |

### PE / Windows

| Terme | Définition |
|-------|------------|
| **PE** | Portable Executable — format des `.exe`/`.dll` Windows |
| **Authenticode** | Signature numérique d'un PE par Microsoft |
| **Rich header** | Empreinte du linker MSVC, présente dans tout binaire MSVC légitime |
| **TLS callbacks** | Fonctions exécutées AVANT le entry-point (vecteur d'évasion) |
| **Section WX** | Section avec droits Write+eXecute → injection probable |
| **Sysmon** | Outil Microsoft Sysinternals qui enrichit les logs Windows |
| **ETW** | Event Tracing for Windows — instrumentation kernel |

### Architecture

| Terme | Définition |
|-------|------------|
| **APScheduler** | Lib Python de scheduling (cron, intervalles) |
| **JWT** | JSON Web Token — token signé pour authentification |
| **Multipart** | Encoding HTTP pour upload de fichiers |
| **OpenAPI** | Spec auto-générée par FastAPI à `/docs` |
| **Pydantic** | Validation de données Python via type hints |
| **RQ** | Redis Queue — workers async simples |
| **Tenacity** | Lib Python de retry avec backoff |

## Suite

→ [10 — Roadmap (Phases C → F)](10-roadmap.md)
