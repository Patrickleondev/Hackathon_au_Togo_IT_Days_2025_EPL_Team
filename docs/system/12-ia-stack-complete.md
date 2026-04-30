# 12 — La stack IA de GuardIAn, couche par couche

> **Pour qui ?** Ce document est écrit pour **trois publics en même temps** :
>
> - **Les utilisateurs finaux** (analystes SOC, RSSI, équipes IT) qui veulent
>   savoir *comment* la plateforme prend ses décisions et *pourquoi* ils peuvent
>   lui faire confiance.
> - **Les contributeurs** qui veulent ajouter un détecteur, ré-entraîner un
>   modèle ou brancher un nouveau flux de threat intelligence.
> - **Les investisseurs et personnes non techniques** qui veulent comprendre, en
>   langage clair, ce qui rend GuardIAn différent d'un antivirus classique et
>   pourquoi il résiste à des attaquants modernes (rançongiciels, APT).
>
> Chaque section commence par une **explication grand public** (encadré « En
> clair »), suivie des **détails techniques** (chemins de fichiers, seuils,
> algorithmes) pour aller plus loin.

---

## Table des matières

1. [Vue d'ensemble : pourquoi plusieurs IA et non une seule](#1-vue-densemble)
2. [Le pipeline en 7 couches](#2-le-pipeline-en-7-couches)
3. [Couche par couche : qui fait quoi](#3-couche-par-couche)
   - [Couche 1 — Agent local : le poste de garde](#couche-1--agent-local-windowslinuxmacos)
   - [Couche 2 — Heuristiques statiques](#couche-2--heuristiques-statiques-au-backend)
   - [Couche 3 — Ensemble Machine Learning](#couche-3--ensemble-machine-learning)
   - [Couche 4 — Threat Intelligence](#couche-4--threat-intelligence-le-cerveau-collectif)
   - [Couche 5 — Analyse statique profonde](#couche-5--analyse-statique-profonde-static-v2)
   - [Couche 6 — Règles YARA](#couche-6--règles-yara-la-mémoire-des-experts)
   - [Couche 7 — Détection réseau](#couche-7--détection-réseau-dga-beaconing-ja3)
4. [L'assistant conversationnel (chatbot)](#4-lassistant-conversationnel-chatbot)
5. [Comment GuardIAn résiste aux APT](#5-comment-guardian-résiste-aux-apt)
6. [Système d'entraînement et ré-entraînement des modèles](#6-système-dentraînement)
7. [Pour aller plus loin : pistes ouvertes (Phase D, E, F)](#7-pistes-ouvertes)
8. [FAQ technique pour contributeurs](#8-faq-technique)

---

## 1. Vue d'ensemble

> **En clair :** Un antivirus classique ressemble à un vigile qui lit une liste
> de criminels recherchés. Si le pirate change de chemise (renomme son fichier),
> il passe. GuardIAn fonctionne plutôt comme un aéroport moderne : portique,
> chien renifleur, agent qui observe ton comportement, base de données
> Interpol, et caméras qui surveillent la sortie. Sept contrôles
> indépendants. Pour passer, l'attaquant doit tromper les sept en même temps —
> beaucoup plus difficile.

### 1.1 Le principe : défense en profondeur

GuardIAn ne mise pas sur **un seul modèle d'IA très intelligent**. Cette
approche a deux problèmes connus :

- Un modèle unique a un **angle mort** : un attaquant qui connaît son
  fonctionnement (par exemple un .exe avec une signature légitime volée) le
  trompe entièrement.
- Un seul modèle est une **boîte noire** : difficile à auditer, à expliquer à un
  analyste, à corriger.

À la place, GuardIAn empile **sept couches de détection indépendantes**.
Chacune utilise un signal différent (lexical, statistique, ML, communautaire,
binaire, comportemental, réseau). Une menace doit échouer sur les **sept** pour
passer. Et chaque couche est **explicable** : on peut dire à l'analyste *pourquoi*
on a déclenché.

### 1.2 Trois grandes familles de signaux

| Famille | Question posée | Couches concernées |
|---|---|---|
| **Statique** (le fichier sans l'exécuter) | « À quoi ressemble ce fichier ? » | Couches 2, 3, 5, 6 |
| **Renseignement** (ce que le monde sait déjà) | « Quelqu'un a-t-il déjà vu ce fichier ailleurs ? » | Couche 4 |
| **Comportemental / réseau** (ce que ce processus fait) | « Comment se comporte-t-il une fois lancé ? » | Couches 1, 7 |

### 1.3 Tableau récapitulatif des modèles

| # | Composant | Type | Sortie | Fichier principal |
|---|---|---|---|---|
| 1 | Heuristiques agent | Règles + entropie | `(suspect: bool, raison)` | [agent/guardian_agent/heuristics.py](../../agent/guardian_agent/heuristics.py) |
| 2 | Heuristiques backend | Règles + patterns regex | score `[0,1]` | [backend/app/ml/features.py](../../backend/app/ml/features.py) |
| 3 | RandomForest + StandardScaler | ML supervisé (sklearn) | probabilité `[0,1]` | [backend/app/ml/detector.py](../../backend/app/ml/detector.py) |
| 4 | Threat Intelligence | Recherche en base (SHA256, IP, domaine, URL, JA3) | `match | none` | [backend/app/intel/](../../backend/app/intel/) |
| 5 | Static-V2 (PE parser, ssdeep, TLSH) | Parsing structurel + hash flou | features détaillées | [backend/app/ml/static_v2.py](../../backend/app/ml/static_v2.py) |
| 6 | Moteur YARA | Règles communautaires | `liste de règles match` | [backend/app/ml/rules/](../../backend/app/ml/rules/) |
| 7 | DGA + Beaconing + JA3 | Stats + lookup | `score + verdict` | [backend/app/network/](../../backend/app/network/) |
| 8 | Retriever assistant | TF-IDF léger | top-K FAQ | [backend/app/assistant/retriever.py](../../backend/app/assistant/retriever.py) |

---

## 2. Le pipeline en 7 couches

```text
┌─────────────────────────────────────────────────────────────────────┐
│                            POSTE UTILISATEUR                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  COUCHE 1 — AGENT LOCAL (Windows/Linux/macOS)                │   │
│  │  • Surveille les dossiers (watchdog)                         │   │
│  │  • Triage local : entropie, extension, patterns              │   │
│  │  • Si suspect → upload au backend                            │   │
│  └──────────────────┬───────────────────────────────────────────┘   │
└─────────────────────┼───────────────────────────────────────────────┘
                      │  HTTPS + JWT
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                              BACKEND                                 │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ COUCHE 4 — THREAT INTEL (court-circuit prioritaire)        │    │
│   │ Le hash SHA-256 est-il dans intel_hashes ? → conf ≥ 0.95  │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │ non                                        │
│                         ▼                                            │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ COUCHE 2 — HEURISTIQUES (toujours active)                  │    │
│   │ • Entropie de Shannon                                      │    │
│   │ • Mismatch magic-byte / extension                          │    │
│   │ • Patterns regex (ransom note, vssadmin, BTC, .onion...)   │    │
│   │ → score_heuristic ∈ [0, 1]                                 │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │                                            │
│                         ▼                                            │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ COUCHE 3 — ML ENSEMBLE (si modèle chargé)                  │    │
│   │ Vecteur 8 features → RandomForest                          │    │
│   │ → score_ml ∈ [0, 1]                                        │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │                                            │
│                         ▼                                            │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ COUCHE 5 — STATIC-V2 (optionnel, Phase B)                  │    │
│   │ • PE parser (sections, imports, packers)                   │    │
│   │ • Hash flou (ssdeep, TLSH, imphash) vs intel               │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │                                            │
│                         ▼                                            │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │ COUCHE 6 — YARA                                             │    │
│   │ Règles génériques + YARAify (communauté abuse.ch)          │    │
│   │ → matched_rules: list[str]                                 │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │                                            │
│                         ▼                                            │
│   ┌────────────────────────────────────────────────────────────┐    │
│   │           AGRÉGATION → DetectionResult                      │    │
│   │ confidence = pondération (heuristic, ml, yara, intel)       │    │
│   │ severity = low / medium / high / critical                   │    │
│   │ verdict appliqué : threshold_low / medium / high            │    │
│   └─────────────────────┬──────────────────────────────────────┘    │
│                         │                                            │
│   ┌─────────────────────┴──────────────────────────────────────┐    │
│   │ COUCHE 7 — DÉTECTION RÉSEAU (en parallèle, asynchrone)     │    │
│   │ • DGA  : entropie + bigrammes anglais sur le label 2LD     │    │
│   │ • Beaconing : test de Rayleigh sur les timestamps          │    │
│   │ • JA3/JA4 : lookup TLS fingerprint vs liste C2 connus      │    │
│   └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Note importante.** L'ordre n'est pas séquentiel partout : la couche 4
(Threat Intel) est un **court-circuit** : si le hash exact d'un fichier est
déjà connu comme malveillant, on s'arrête là (gain de temps + signal le plus
fiable). Les autres couches s'enchaînent et leurs scores sont **agrégés** dans
un `DetectionResult` unique.

---

## 3. Couche par couche

### Couche 1 — Agent local (Windows/Linux/macOS)

> **En clair :** un petit logiciel installé sur chaque ordinateur du parc. Il
> surveille les dossiers sensibles (Documents, Téléchargements, partages
> réseau...) et n'envoie au serveur central que ce qui mérite un examen plus
> poussé. Cela protège la vie privée (rien d'inutile ne quitte la machine) et
> la bande passante.

**Fichiers :** [`agent/guardian_agent/`](../../agent/guardian_agent/)
- `watcher.py` — surveillance fichiers via la lib `watchdog`
- `heuristics.py` — triage local (entropie, extensions, patterns regex)
- `client.py` — client HTTP (enrôlement, heartbeat, upload)
- `config.py` — configuration

**Ce que l'agent décide tout seul (sans demander au serveur) :**

1. **Filtre par extension** : `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.scr`,
   `.dll`, `.zip`, `.7z`, `.rar`, `.docm`, `.xlsm`, `.js`, `.hta`...
2. **Filtre par taille** : `upload_max_mb` (défaut 50 MB) — un fichier de 4 GB
   ne sera pas remonté.
3. **Calcul d'entropie** : un fichier `.txt` qui a une entropie de 7.9
   bits/octet est probablement chiffré ou compressé (anormal pour du texte).
4. **Patterns lexicaux** : présence de chaînes comme `vssadmin delete shadows`,
   `bcdedit /set recoveryenabled No`, ou des notes de rançon en plusieurs
   langues.

Si **au moins une** de ces alertes se déclenche, le fichier est haché (SHA-256)
puis téléversé vers `POST /api/analyze/agent-file` avec un JWT d'agent.

**Sortie :** `(is_suspicious: bool, reason: str)`

**Sécurité de l'agent :**
- Enrôlement par secret pré-partagé : header `X-Enrollment-Secret`
  (`agent_enrollment_secret` côté backend, jamais commité dans Git).
- Une fois enrôlé, l'agent reçoit un **JWT spécifique** valide
  `jwt_agent_ttl_days` (défaut 30 jours).
- Heartbeat toutes les `heartbeat_sec` secondes (défaut 30 s) → détection
  d'agent compromis ou hors-ligne.

---

### Couche 2 — Heuristiques statiques (au backend)

> **En clair :** quand un fichier suspect arrive au serveur, on le passe au
> rayon X avant tout traitement intelligent. Ce sont des règles d'expert
> écrites « à la main », rapides, déterministes, faciles à expliquer en
> tribunal ou à un client. Aucun apprentissage ici — pas de boîte noire.

**Fichiers :**
- [`backend/app/ml/features.py`](../../backend/app/ml/features.py) — extracteur de features
- [`backend/app/ml/detector.py`](../../backend/app/ml/detector.py) — orchestration

**Ce qui est calculé sur les 4 premiers MiB du fichier (`feature_max_read_bytes`) :**

| Feature | Description | Anormal si... |
|---|---|---|
| `entropy` | Entropie de Shannon par blocs de 64 KiB | ≥ 7.5 bits/octet sur du texte ou un .pdf |
| `magic_mismatch` | Le contenu (magic bytes) correspond-il à l'extension ? | `.exe` qui commence par `PK` (ZIP camouflé) |
| `extension_score` | Table de scores par extension | `.bat=0.65`, `.exe=0.55`, `.scr=0.75` |
| `pattern_count` | Nombre de patterns regex matchés | ≥ 3 patterns différents → suspect |
| `high_entropy_block` | Bloc unique très chiffré dans un fichier sinon normal | dropper avec payload chiffré inline |

**Bibliothèque de patterns** (extrait de `features.py` lignes 54–76) :

| Famille | Exemples détectés |
|---|---|
| `encryption_api` | `CryptEncrypt`, `AES_encrypt`, `RSA_public_encrypt` |
| `ransom_note` | « your files have been encrypted », « pay in bitcoin » |
| `shadow_copy_delete` | `vssadmin delete shadows /all /quiet` |
| `wbadmin_delete` | `wbadmin delete catalog` |
| `bcdedit_recovery` | `bcdedit /set recoveryenabled No` |
| `powershell_obfuscated` | `-enc`, `-encodedcommand`, `FromBase64String` |
| `downloader` | `certutil -urlcache`, `bitsadmin /transfer`, `wget`, `curl` |
| `persistence` | `\Run\`, `\RunOnce\`, `schtasks /create`, `reg add ...\Run` |
| `tor_onion` | URL en `.onion` |
| `btc_wallet` | regex d'adresse Bitcoin |

**Sortie :** `score_heuristic ∈ [0, 1]`. C'est ce score qui démarre tout.

---

### Couche 3 — Ensemble Machine Learning

> **En clair :** une fois les indices manuels collectés, on les donne à un
> modèle entraîné sur des centaines d'exemples bénins et malveillants. Il
> repère des combinaisons subtiles que les règles humaines ne voient pas (par
> exemple : « petit fichier + entropie moyenne + 2 patterns persistance + pas
> de magic mismatch = très souvent un dropper »).

**Fichier :** [`backend/app/ml/detector.py`](../../backend/app/ml/detector.py) (lignes 77–92)

**Modèle :** `RandomForestClassifier` + `StandardScaler` empilés dans un
[`Pipeline`](https://scikit-learn.org/stable/modules/generated/sklearn.pipeline.Pipeline.html)
sklearn, sérialisé en `models/detector.joblib`.

**Pourquoi RandomForest et pas un réseau de neurones ?**

| Critère | RandomForest | Deep Learning |
|---|---|---|
| Données nécessaires | Quelques centaines d'exemples suffisent | Des dizaines de milliers |
| Temps d'inférence | < 1 ms | 10–100 ms (GPU recommandé) |
| Explicabilité | Feature importance native | Boîte noire (SHAP requis) |
| Audit RGPD / sécurité | Trivial | Complexe |
| Empreinte mémoire | ~ 5 MB | 100 MB – plusieurs GB |
| Robustesse au shift de distribution | Élevée | Sensible |

Pour un MVP destiné à des PME togolaises et à des contributeurs hackathon, le
choix RandomForest est pragmatique. La Phase E ouvrira la porte à un LSTM
**spécialisé** sur la détection DGA, là où le deep learning excelle vraiment.

**Vecteur d'entrée — 8 floats** (`FileFeatures.to_vector()`) :

```python
[
    size_norm,         # taille / 50_MB
    entropy_norm,      # entropie / 8.0
    int(magic_mismatch),
    extension_score,
    pattern_count_norm,    # patterns / 20
    int(high_entropy_block),
    0.0,               # réservé Phase B (ssdeep proximity)
    0.0,               # réservé Phase B (PE imports score)
]
```

**Sortie :** `score_ml ∈ [0, 1]` (probabilité que le sample soit malveillant).

**Comportement dégradé :** si `detector.joblib` est absent (premier déploiement,
fichier corrompu, version incompatible), le détecteur **continue de fonctionner**
avec uniquement les couches 2, 4, 6. Le frontend affiche `ml=null` dans le
résultat — l'utilisateur sait qu'il manque un signal.

---

### Couche 4 — Threat Intelligence (le « cerveau collectif »)

> **En clair :** toutes les heures, GuardIAn télécharge la liste des
> cybercriminels connus dans le monde. Si le fichier qu'on analyse est dans
> cette liste, pas besoin d'aller plus loin : on sait déjà que c'est mauvais,
> et avec quelle famille de malware on a affaire. C'est l'équivalent d'Interpol
> pour les fichiers numériques.

**Module :** [`backend/app/intel/`](../../backend/app/intel/) (9 modules Python)

**Service principal :** `intel/service.py`. **Planificateur :** `intel/scheduler.py`
(via APScheduler), tourne toutes les `intel_update_interval_hours` heures
(défaut 6).

**Flux surveillés (par défaut) :**

| Flux | Source | Type d'IOC | Fournit | Clé requise ? |
|---|---|---|---|---|
| **MalwareBazaar** | abuse.ch | hashes (SHA-256, MD5, SHA-1) + famille | `intel_hashes` | abuse.ch Auth-Key (gratuite) |
| **URLhaus** | abuse.ch | URLs malveillantes | `intel_indicators` | abuse.ch Auth-Key |
| **ThreatFox** | abuse.ch | C2 (IP, domaine, hash) | les deux | abuse.ch Auth-Key |
| **Feodo Tracker** | abuse.ch | C2 trojans bancaires | `intel_indicators` | abuse.ch Auth-Key |
| **YARAify** | abuse.ch | règles YARA communautaires | `intel_yara_rules` | abuse.ch Auth-Key |
| **AbuseIPDB** | abuseipdb.com | IPs malveillantes | `intel_indicators` | clé payante |
| **OTX (Alien Vault)** | otx.alienvault.com | « pulses » (campagnes APT) | les deux | clé gratuite |

**Politique de rétention :** `intel_retention_days` (défaut 90 jours). Au-delà,
les indicateurs sont supprimés automatiquement. **Plafond par flux :**
`intel_max_rows_per_feed` (défaut 250 000 lignes) pour ne pas saturer la base.

**Pourquoi c'est crucial :** dans plus de 60 % des cas réels d'attaque, le
binaire utilisé a déjà été observé quelque part dans les 30 jours précédents.
Cette couche transforme GuardIAn en **client** d'une intelligence collective
mondiale, gratuite, mise à jour en quasi temps réel.

**Court-circuit prioritaire :** si une couche TI matche, on retourne
`confidence ≥ 0.95` immédiatement. Le ML et l'heuristique sont **doublés** par
ce signal (signal le plus fiable disponible).

---

### Couche 5 — Analyse statique profonde (Static-V2)

> **En clair :** quand le simple « rayon X » ne suffit pas, on dissèque le
> fichier comme un mécanicien démonte un moteur. On regarde sa structure
> interne (sections, imports, signatures), et on calcule des « empreintes
> floues » qui repèrent des variantes même si l'attaquant a changé un octet
> pour échapper aux signatures classiques.

**Fichier :** [`backend/app/ml/static_v2.py`](../../backend/app/ml/static_v2.py)

**Statut :** code écrit, **pas encore intégré au scoring principal** (Phase B
en cours d'achèvement). Disponible via les tests (`test_static_v2.py`) et
appelable directement.

**Trois techniques :**

#### 5.1 Hash flou
- **ssdeep** (distance Levenshtein) — détecte un fichier identique à 95 % à un
  malware connu. Robuste à l'ajout de padding ou au repacking partiel.
- **TLSH** (Trend Micro Locality Sensitive Hash) — meilleur sur les gros
  fichiers (≥ 50 KB), normalisé.
- **imphash** — hash basé uniquement sur la table d'imports d'un PE Windows.
  Très efficace pour identifier la *famille* d'un malware (deux droppers
  différents qui appellent les mêmes APIs ont souvent le même imphash).

#### 5.2 PE parser (Windows .exe/.dll)
Via la lib `pefile`. Extrait :
- Anomalies de sections (noms suspects `.UPX0`, headers désalignés)
- **Imports suspects** classés en 7 catégories :
  - `process_injection` (`VirtualAllocEx`, `WriteProcessMemory`,
    `CreateRemoteThread`)
  - `anti_debug` (`IsDebuggerPresent`, `NtQueryInformationProcess`)
  - persistance, crypto, réseau, fichier, registre
- Présence d'un **Rich Header** (signature de la chaîne de compilation
  Microsoft)
- **Authenticode** (le binaire est-il signé par un éditeur connu ?)
- TLS callbacks (code C++ d'initialisation, parfois utilisé pour cacher le
  vrai entry point)

#### 5.3 Détection de packers
UPX, Themida, VMProtect, ASPack, Enigma, PECompact — repérés via les noms de
sections et signatures d'octets. Un binaire packé n'est pas malveillant *par
nature*, mais c'est un **signal de risque** (légitime business apps :
< 5 % packées ; malware : > 60 %).

---

### Couche 6 — Règles YARA (la mémoire des experts)

> **En clair :** YARA, c'est le langage standard des chasseurs de malware.
> Quand un analyste découvre une nouvelle souche, il écrit une règle YARA qui
> décrit ses signatures. GuardIAn télécharge automatiquement les règles
> publiées par la communauté mondiale (via abuse.ch / YARAify) et les applique
> à chaque fichier scanné. Une règle qui matche dit en plus *quelle famille*
> est en cause (Lockbit, Conti, BlackCat...).

**Fichiers :**
- [`backend/app/ml/rules/generic.yar`](../../backend/app/ml/rules/) — règles
  internes maintenues par l'équipe
- Table SQL `intel_yara_rules` — règles communautaires fetchées par YARAify

**Moteur :** `yara-python` (lib officielle, importée à la demande). Si elle
n'est pas installable (Windows minimal), le détecteur **fonctionne quand
même** sans cette couche — on perd un signal mais le système ne plante pas.

**Sortie :** `matched_rules: list[str]` (noms des règles déclenchées). Affiché
dans l'interface analyste pour fournir un contexte explicable
(« Lockbit_Variant_2024_03 »).

---

### Couche 7 — Détection réseau (DGA, Beaconing, JA3)

> **En clair :** les rançongiciels modernes ne se contentent pas de chiffrer.
> Ils communiquent avec un serveur distant (« command-and-control » ou C2)
> pour recevoir la clé, exfiltrer des fichiers, recevoir des ordres. Cette
> couche écoute le trafic réseau et repère trois signaux qu'un humain ne peut
> pas voir à l'œil nu.

**Module :** [`backend/app/network/`](../../backend/app/network/)

**Sources d'événements** (un sidecar **Suricata** ou **Zeek** ou les agents
eux-mêmes les remontent) :
- `POST /api/network/events` — événements pré-parsés
- `POST /api/network/events/raw` — Suricata EVE-JSON brut, ou Zeek TSV

#### 7.1 Détection DGA — `network/dga.py`
**DGA** = Domain Generation Algorithm. Un malware moderne ne se connecte pas à
un domaine fixe (trop facile à bloquer) — il en génère des centaines par
jour : `xkjqwerty.biz`, `mzpoiuhgf.xyz`, `qweasdzxc.top`. Notre détecteur
score chaque domaine sur **6 axes** :

| Axe | Comportement attendu d'un domaine légitime | Comportement DGA |
|---|---|---|
| `entropy` | Faible (mots du dictionnaire) | Élevée |
| `bigram_logp_mean` | Bigrammes anglais courants | Bigrammes improbables |
| `vowel_ratio` | 0.30 – 0.55 | Souvent < 0.20 |
| `max_consonant_run` | ≤ 4 (« strength » = 5, rare) | ≥ 5 fréquent |
| `digit_ratio` | Faible | Élevé sur certaines familles |
| `length` | 5 – 15 caractères | Souvent > 12 |

**Sortie :** `score ∈ [0, 1]` blendé. Seuil pratique : `score ≥ 0.65`.

**Note :** la Phase E remplacera cette heuristique par un **LSTM character-level**
entraîné sur 1 M+ de domaines DGA collectés (DGArchive). Référence : Yu et al.,
*Inline DGA Detection with Deep Networks*, ICDM 2017.

#### 7.2 Beaconing — `network/beaconing.py`
**Beaconing** = un implant qui « rappelle à la maison » à intervalle régulier
(ex : toutes les 5 minutes). Cobalt Strike, Empire, Sliver font ça.

**Algorithme :** test de **Rayleigh** sur les timestamps de connexion d'un
même couple `(src_ip, dst_ip[, dst_port])`.

$$ R(T) = \frac{1}{N} \left| \sum_{k=1}^{N} e^{2\pi i \cdot t_k / T} \right| $$

Si les timestamps sont régulièrement espacés à période $T$, $R(T)$ est proche
de 1. S'ils sont aléatoires, $R(T)$ tend vers 0.

**Sortie :** `BeaconResult { period_s, score, jitter, verdict }`.
Verdicts : `benign | suspicious | beacon_likely | unknown`.

**Seuil opérationnel :** `score ≥ 0.65 AND jitter ≤ 0.15` → `beacon_likely`.

**Référence :** RITA (Real Intelligence Threat Analytics), ActiveCM.

#### 7.3 JA3 / JA4 — `network/ja3.py`
**JA3 / JA4** = empreintes du *handshake* TLS. Chaque outil C2 a une signature
caractéristique (Cobalt Strike par défaut, Empire, Trickbot, Emotet, Tor,
Sliver...). Même si l'attaquant utilise un certificat valide Let's Encrypt,
son client TLS le trahit.

GuardIAn maintient :
- une **liste interne** de ~10 fingerprints connus C2 (en dur dans le code)
- une **table `ja3_fingerprints`** alimentée par abuse.ch SSLBL et SalesForce

**Sortie de `GET /api/network/ja3/{fp}` :** `{ family, source, description }`
ou 404.

---

## 4. L'assistant conversationnel (chatbot)

> **En clair :** un chatbot intégré dans l'interface répond aux questions des
> utilisateurs (« comment installer l'agent ? », « pourquoi ce fichier est-il
> classé en orange ? »). Par défaut, il répond uniquement à partir d'une base
> de connaissances locale — **aucun appel sortant**, aucune donnée envoyée à
> un service tiers. C'est la garantie vie privée.
>
> Une organisation qui le souhaite peut, en une variable d'environnement,
> brancher Claude (Anthropic), GPT (OpenAI), Mistral, OpenRouter ou Ollama
> (local) pour des réponses plus libres. C'est optionnel. Et c'est explicite :
> l'interface affiche **« Knowledge base only »** quand aucun LLM n'est branché.

**Module :** [`backend/app/assistant/`](../../backend/app/assistant/)
- `kb.py` — 30 entrées FAQ bilingues (FR/EN)
- `retriever.py` — recherche TF-IDF allégée (Python pur, pas de scikit-learn)
- `providers.py` — bridge vers 5 LLMs via httpx (pas de SDK)
- `service.py` — arbre de décision : KB → LLM → fallback

**Arbre de décision :**

```
question utilisateur
     │
     ▼
[retriever] cherche dans la FAQ
     │
     ├─ score top ≥ 0.32  →  réponse KB locale (source="kb")
     │
     └─ score top < 0.32
            │
            ▼
       LLM configuré (LLM_PROVIDER ≠ none) ?
            │
            ├─ oui → appel LLM avec contexte top-K FAQ (source="llm")
            │       │
            │       └─ erreur réseau / quota → fallback KB best-effort (source="fallback")
            │
            └─ non → message « contactez un expert » + lien /faq (source="fallback")
```

**Endpoints publics** (pas d'auth, mais rate-limit `30/min` par IP) :
- `POST /api/chat` — pose une question
- `GET /api/chat/faq` — récupère le catalogue FAQ
- `GET /api/chat/suggestions` — chips suggérés
- `GET /api/chat/provider` — savoir si un LLM est actif

**Privacy-first par défaut :** `LLM_PROVIDER=none` ⇒ zéro appel sortant.

---

## 5. Comment GuardIAn résiste aux APT

> **APT** = Advanced Persistent Threat. Pas un script kiddie, mais un acteur
> étatique ou un groupe criminel organisé (APT28, Lazarus, FIN7...). Leur mode
> opératoire : entrer discrètement, rester des mois, exfiltrer des données
> stratégiques, bouger latéralement entre les machines, déployer le
> rançongiciel **en dernier** (parfois après 6 mois de présence).
>
> Un APT moderne ne se laisse pas attraper par une signature antivirus. Il
> faut **plusieurs signaux de bas niveau** corrélés dans le temps. C'est
> exactement la philosophie de GuardIAn.

### 5.1 Signaux APT couverts aujourd'hui

| Tactique APT (MITRE ATT&CK) | Couche GuardIAn | Comment c'est détecté |
|---|---|---|
| **T1486** — Data Encrypted for Impact | 2, 3, 6 | Patterns ransom note, `vssadmin delete shadows`, règles YARA familles ransomwares |
| **T1490** — Inhibit System Recovery | 2 | `bcdedit /set recoveryenabled No`, `wbadmin delete catalog` |
| **T1547** — Boot or Logon Autostart Execution | 2 | Patterns `\Run\`, `\RunOnce\`, `schtasks /create` |
| **T1059.001** — PowerShell | 2 | `-enc`, `-encodedcommand`, `FromBase64String` |
| **T1105** — Ingress Tool Transfer | 2 | `certutil -urlcache`, `bitsadmin /transfer` |
| **T1071** — Application Layer Protocol (C2) | 7 | Beaconing (Rayleigh) |
| **T1573** — Encrypted Channel | 7 | Empreinte JA3/JA4 vs Cobalt Strike, Empire, Sliver |
| **T1568** — Dynamic Resolution / DGA | 7 | Score DGA lexical |
| **T1102** — Web Service / abused legit hosts | 4 | URLhaus, ThreatFox |
| **T1027** — Obfuscated Files | 2, 3, 5 | Entropie, packer detection |
| **T1566** — Phishing | 4 | URLhaus, MalwareBazaar |

### 5.2 Pourquoi c'est efficace contre les APT

1. **Multi-signal.** Un APT peut éviter un signal en se contentant de
   *living-off-the-land* (utiliser PowerShell signé Microsoft). Mais il finira
   par **toucher un autre signal** : le beaconing TLS (couche 7), la requête
   sur un domaine DGA, le hash d'un implant connu (couche 4).
2. **Threat intel à 6 h de fraîcheur.** Quand un nouveau loader Cobalt Strike
   apparaît dans la nature, il est généralement publié sur MalwareBazaar dans
   les 48 h. La fenêtre où il passe inaperçu est donc bornée.
3. **Beaconing → seul signal qui ne dépend PAS du fichier.** Même si
   l'attaquant remplace son binaire toutes les heures (technique du
   *fingerprint rotation*), il continue de communiquer avec son C2 toutes les
   X minutes — et ça, on le voit.
4. **Chaque détection est explicable.** L'analyste voit *pourquoi* l'alerte
   s'est déclenchée (quels patterns, quelle règle YARA, quel hash matché).
   Ça raccourcit drastiquement le temps de qualification (TP/FP).

### 5.3 Ce que GuardIAn ne fait PAS encore

Pour la transparence (et parce qu'on parle à des contributeurs) :

| Capacité | Statut | Phase prévue |
|---|---|---|
| Ingestion Sysmon / Windows Event Log | ❌ Non implémenté | Phase D |
| Règles Sigma | ❌ Non implémenté (YARA seulement) | Phase D |
| Canary tokens / déception | ❌ Non implémenté | Phase D |
| Corrélation latérale entre endpoints | ❌ Non implémenté | Phase F |
| Surveillance temps-réel du registre Windows | ⚠️ Patterns lexicaux uniquement | Phase D |
| Mapping MITRE ATT&CK formel | ⚠️ Implicite, pas de table | Phase D |
| LSTM character-level pour DGA | ❌ Heuristique seulement | Phase E |
| Boucle de feedback / online learning | ❌ Non implémenté | Phase E |

C'est volontaire : un MVP solide qui détecte vraiment **les rançongiciels et
les APT classiques d'aujourd'hui**, plutôt qu'une démo qui fait tout à 30 %.

---

## 6. Système d'entraînement

### 6.1 Philosophie

> **En clair :** notre modèle de ML est entraîné sur des fichiers que vous
> fournissez (ou sur une base synthétique de secours). Vous gardez le contrôle.
> Pas d'envoi à un cloud d'entraînement. Pas de modèle propriétaire fermé. Tout
> est ré-exécutable, reproductible, auditable.

### 6.2 Script d'entraînement principal

**Fichier :** [`backend/scripts/train_detector.py`](../../backend/scripts/train_detector.py)

**Données d'entrée :**

```
${MODELS_DIR}/../samples/
    ├─ benign/         (jusqu'à 500 fichiers .exe, .dll, .pdf, etc.)
    └─ malicious/      (jusqu'à 500 fichiers, à manipuler dans une VM)
```

**Mode dégradé :** si les dossiers sont vides ou absents, le script génère
**600 échantillons synthétiques** (seed=42, reproductible) — suffisant pour un
premier modèle de démo, mais à remplacer en production.

**Pipeline :** `StandardScaler` → `RandomForestClassifier`. Sortie sérialisée
en `models/detector.joblib` (~5–50 MB selon le nombre d'arbres).

**Métriques :** classification report (precision, recall, F1) imprimé sur la
console.

### 6.3 Comment un contributeur ré-entraîne

```bash
# 1. Préparer les samples (à manipuler dans une VM ! les fichiers malveillants
#    sont à manier comme des explosifs)
mkdir -p /var/lib/guardian/samples/{benign,malicious}
# Déposer .exe, .dll, .pdf, .docm, etc. dans benign/
# Déposer les samples vivants dans malicious/

# 2. Lancer l'entraînement depuis le conteneur ou en local
cd backend
python -m scripts.train_detector \
    --benign /var/lib/guardian/samples/benign \
    --malicious /var/lib/guardian/samples/malicious

# 3. Vérifier la sortie
ls -lh /var/lib/guardian/models/detector.joblib
# > -rw-r--r-- 1 user user 12M Apr 30 18:42 detector.joblib

# 4. Redémarrer le backend pour charger le nouveau modèle
docker compose restart backend
```

### 6.4 Sources de données recommandées

| Source | Type | Licence |
|---|---|---|
| **MalwareBazaar** (téléchargement direct) | malware vivant | CC0, commercial OK |
| **VirusShare** (gratuit après demande) | malware vivant + classés | recherche/non-commercial |
| **TheZoo** (GitHub) | malware historique | MIT |
| **EICAR** | sample test inoffensif | gratuit |
| **DikeDataset** (PE features) | features pré-extraites | recherche |
| **EMBER** (Endgame) | features PE 2017+2018 | Apache 2.0 |
| **DGArchive** (Phase E) | domaines DGA labelisés | recherche |

⚠️ **Sécurité d'entraînement.** Les samples malveillants doivent être manipulés
dans une **VM isolée** (pas de partage, pas de réseau). Idéalement, l'entraînement
tourne dans un environnement dédié et le `detector.joblib` final est
copié vers la prod (pas l'inverse).

### 6.5 Boucle de retour utilisateur (manuelle aujourd'hui, automatique en Phase E)

**Aujourd'hui (manuel) :**
1. Un analyste marque une alerte comme **faux positif** dans l'UI →
   `POST /api/threats/{id}/dismiss`.
2. L'admin exporte la liste des FP : `GET /api/threats?status=dismissed`.
3. Les fichiers correspondants sont copiés dans `samples/benign/` (ils ne sont
   pas malveillants par définition).
4. Ré-entraînement → cycle de 1 à 5 jours selon la cadence d'alertes.

**Phase E prévue :** déclencheur automatique. Quand on accumule N nouvelles
labélisations, le worker RQ lance un ré-entraînement, écrit un *challenger*
modèle (`detector_candidate.joblib`), évalue ses métriques sur un set de
validation, et **promeut** uniquement si les métriques sont meilleures
(*champion / challenger pattern*).

### 6.6 Versioning des modèles

Aujourd'hui, le `detector.joblib` est écrasé à chaque ré-entraînement. La
Phase E introduira :
- nommage `detector_YYYYMMDD_HHMM.joblib`
- table `model_registry` (id, path, trained_at, metrics_json, status:
  candidate/champion/archived)
- rollback en une commande : `python -m scripts.promote_model
  detector_20260420_1842.joblib`

---

## 7. Pistes ouvertes

> **Pour les contributeurs et investisseurs :** voici les briques sur
> lesquelles travailler. Chacune est une feature isolée — un développeur peut
> en porter une sans toucher au reste.

### Phase D — APT & comportement
- Ingestion **Sysmon** (canal Microsoft-Windows-Sysmon/Operational)
- Parser **règles Sigma** → SQL/regex (lib `sigma-cli` existe en Python)
- **Canary tokens** (fichiers leurres : si l'un est ouvert, l'agent alerte
  immédiatement)
- **Surveillance temps-réel registre** Windows (RegNotifyChangeKeyValue)
- Table de mapping MITRE ATT&CK explicite (`mitre_techniques` avec lien sur
  chaque alerte)

### Phase E — IA avancée
- **LSTM char-level** pour DGA (PyTorch ; entraîné sur DGArchive + Alexa Top 1M
  inversé en bénin)
- **Embedding sémantique** des binaires (Asm2Vec, PalmTree) pour matcher des
  variantes inconnues
- **Champion/challenger** automatique sur le détecteur principal
- Boucle de **feedback actif** (UI analyste → ré-entraînement worker)

### Phase F — Corrélation cross-endpoint
- Agrégation des événements de *plusieurs* agents → graphe de mouvement latéral
- Détection de **patterns Kerberos** (Pass-the-Hash, Golden Ticket, Kerberoasting)
- Heatmap par utilisateur AD (« cet user a touché 47 machines en 1 h, anormal »)

### Phase G — Réponse automatisée (SOAR)
- Playbooks YAML (« si beacon_likely + JA3 = Cobalt Strike → isoler la
  machine via API EDR »)
- Intégration Wazuh, TheHive, Cortex
- Webhook Slack / Mattermost / Email pour les alertes critiques

---

## 8. FAQ technique

### « Pourquoi ne pas utiliser un seul gros LLM pour tout détecter ? »
Un LLM coûte ~ 10–100 ms par inférence et ~ 0.0001–0.01 USD. Un parc de 1000
endpoints qui scanne 100 fichiers/jour chacun = 100 000 inférences/jour = entre
10 et 1000 USD/jour. Notre RandomForest fait la même chose pour 0 USD et < 1 ms.
Le LLM est gardé pour ce qu'il fait le mieux : répondre à des humains
(chatbot).

### « Qu'arrive-t-il si Internet est coupé ? »
Toutes les couches **sauf** la mise à jour de Threat Intelligence continuent
de fonctionner normalement. Les indicateurs déjà téléchargés restent valides
(rétention 90 jours par défaut). Le LLM optionnel devient indisponible — le
chatbot bascule en mode KB locale.

### « Le modèle peut-il être empoisonné par un attaquant qui submerge les flux TI ? »
Risque réel mais limité :
- abuse.ch a sa propre vérification humaine.
- Plafond `intel_max_rows_per_feed` (250 000 lignes).
- Nous ne **trustons jamais** un seul flux : il faut au moins une corroboration
  (hash *et* règle YARA *et* heuristique) pour `confidence ≥ 0.95`.
- Mais oui, c'est une faiblesse théorique d'une approche TI. La défense
  est de **ne pas y mettre 100 % du poids** — et c'est exactement le
  design de GuardIAn.

### « Pourquoi pas un EDR commercial (CrowdStrike, SentinelOne) ? »
- Coût : 50–150 USD/endpoint/an. Pour 1000 postes c'est 50 000–150 000 USD/an.
- Souveraineté : les données partent dans un cloud étranger (US le plus
  souvent). Problématique pour une administration africaine, un ministère, un
  opérateur télécom ou une banque locale.
- Boîte noire : impossible d'auditer l'algorithme, impossible de comprendre
  pourquoi telle alerte a été levée ou ratée.
- GuardIAn vise les **PME africaines, administrations, écoles, ONG** qui n'ont
  ni le budget ni le besoin d'un EDR commercial — mais qui ont absolument
  besoin de protection contre les rançongiciels.

### « Comment puis-je auditer ce que mes données deviennent ? »
- Tout le code est open-source : [github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team](https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team)
- Aucune télémétrie sortante par défaut. Les seuls appels sortants sont les
  flux TI (configurables individuellement, et chacun peut être désactivé).
- Le LLM optionnel est désactivé par défaut. S'il est activé, l'opérateur sait
  exactement quel provider et quel modèle (affiché dans le chatbot lui-même).

### « Comment je contribue ? »
1. Fork le repo.
2. Lis [09-CONTRIBUTING.md](../09-CONTRIBUTING.md).
3. Choisis une issue taggée `good first issue` ou `help wanted`.
4. Discute du design dans une issue avant de coder (surtout pour les nouveaux
   détecteurs).
5. PR avec tests + un paragraphe explicatif dans `docs/system/`.

---

**Voilà la stack IA de GuardIAn dans son intégralité, sans triche, sans
omission.** Si une partie n'est pas claire, ouvre une issue ou pose la question
au chatbot dans l'interface — il connaît cette doc.
