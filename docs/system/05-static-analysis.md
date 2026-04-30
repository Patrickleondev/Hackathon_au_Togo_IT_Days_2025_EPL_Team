# 05 — Analyse statique avancée (Phase B)

> **Objectif** : extraire des signaux *structurels* qu'un attaquant ne peut pas masquer en flippant 1 byte.

## Le problème

SHA-256 est cryptographiquement parfait — c'est aussi sa faiblesse pour la détection :

```
sample_v1.exe   →   SHA-256: a3b2…f9
sample_v2.exe   →   SHA-256: 7e44…21   (1 byte modifié)
sample_v3.exe   →   SHA-256: 9c1d…83   (recompilé avec un timestamp diff)
```

Trois variantes du *même malware* → trois hashes différents → la TI exact rate 2/3.

**Solution** : empreintes "floues" (fuzzy hashes) qui restent proches malgré les mutations + parsing PE profond pour extraire la structure.

## Code

Module : [`backend/app/ml/static_v2.py`](../../backend/app/ml/static_v2.py).

## Les 3 empreintes floues

### imphash (Mandiant, 2014)

> Hash MD5 de la liste des imports d'un PE, ordonnés.

```python
import pefile
pe = pefile.PE(data=data)
print(pe.get_imphash())   # "f34d5f2d4577ed6d9ceec516c1f5a744"
```

- **Force** : deux malwares de la même famille partagent souvent leur table d'imports
- **Faiblesse** : recompilation avec un compilateur différent change l'imphash
- **Usage GuardIAn** : `lookup_imphash()` pour matcher les variantes

### ssdeep (Jesse Kornblum, 2006)

> Context-Triggered Piecewise Hash (CTPH). Découpe en blocs selon un *rolling hash*, hash chaque bloc, concatène.

```python
import ssdeep
h = ssdeep.hash(data)            # "768:Wf+0…BcdXw:WfQ…dXw"
sim = ssdeep.compare(h1, h2)      # 0 (différent) → 100 (identique)
```

- **Force** : tolérant aux insertions/suppressions
- **Faiblesse** : O(N²) pour rechercher dans un gros corpus
- **Seuil GuardIAn** : similarity ≥ 70 → match
- **Lib** : nécessite `libfuzzy-dev` (apt) — installé dans le Dockerfile

### TLSH (Trend Micro Locality Sensitive Hash, 2013)

> Locality-sensitive : retourne une **distance numérique** entre deux fichiers.

```python
import tlsh
h = tlsh.hash(data)              # "T1A1B…"  (72 chars)
d = tlsh.diff(h1, h2)             # 0 (identique) → ~1000 (totalement différent)
```

- **Force** : indexable, scalable à des millions de samples (vs ssdeep O(N²))
- **Distance** ≤ 30 → famille quasi-certaine ; ≤ 70 → très similaire ; ≤ 150 → similaire
- **Seuil GuardIAn** : distance ≤ 70 → match

### Comparaison

| Critère | imphash | ssdeep | tlsh |
|---------|---------|--------|------|
| Précision | Très haute | Haute | Très haute |
| Rappel | Moyen | Haut | Très haut |
| Scalabilité | O(1) lookup | O(N²) compare | O(N) compare, indexable |
| Robustesse au repacking | Faible | Moyenne | Forte |

GuardIAn utilise les **3** complémentairement.

## Parsing PE profond

Module `static_v2.py` extrait :

| Champ | Signal |
|-------|--------|
| `is_pe`, `machine`, `is_dll`, `is_driver` | Métadonnées de base |
| `has_signature` | Authenticode présent ? Un PE sans signature en 2026 = suspect |
| `has_rich_header` | Empreinte du linker MSVC. Un binaire MSVC sans Rich header = forgé |
| `has_tls_callbacks` | TLS callbacks = exécution AVANT le entry point → vecteur d'évasion |
| `section_count`, `suspicious_sections` | Sections WX (write+execute) = injection probable |
| `import_count`, `suspicious_import_categories` | API par catégorie : `process_injection`, `anti_debug`, `crypto`, `persistence`… |
| `apt_score` | 0..1, somme pondérée des catégories suspectes |
| `packer`, `packer_evidence` | UPX/Themida/VMProtect/ASPack/MPRESS/Enigma/PECompact/FSG/PEtite/NsPack |

### Taxonomie des imports suspects

10 catégories (extrait) :

```python
"process_injection": {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", ...
}
"anti_debug": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", ...}
"crypto": {"CryptEncrypt", "BCryptEncrypt", ...}
"persistence": {"RegSetValueExA", "CreateServiceA", ...}
"shadow_copy": {"DeleteFileA", "MoveFileExA", ...}
# … 5 autres
```

Chaque catégorie qui matche augmente l'`apt_score` selon des poids définis dans le code.

## Détection de packers

3 niveaux de détection :

1. **Section names** (préféré) : `UPX0`, `.themida`, `.vmp1`, `.aspack`, `.MPRESS1`, …
2. **Byte signatures** (fallback) : `b"UPX!"`, `b"MPRESS"` dans les premiers 4 KiB
3. **Heuristique générique** : `import_count < 10 + section haute entropie` → `generic_packer`

## Mapping ATT&CK automatique

À partir des catégories d'imports, on génère des tags ATT&CK :

| Catégorie d'import | Technique ATT&CK |
|--------------------|------------------|
| `process_injection` | T1055 Process Injection |
| `anti_debug` | T1622 Debugger Evasion |
| `anti_vm` | T1497 Sandbox Evasion |
| `crypto` | T1486 Data Encrypted for Impact |
| `persistence` | T1547 Boot/Logon Autostart |
| `shadow_copy` | T1490 Inhibit System Recovery |
| `network` | T1071 Application Layer Protocol |
| `discovery` | T1082 System Information Discovery |
| Packer détecté | T1027.002 Software Packing |

Ces tags remontent dans `DetectionResult.matched_rules` → SOC voit immédiatement le contexte attaque.

## Intégration au détecteur

Code : [`backend/app/ml/detector.py`](../../backend/app/ml/detector.py) — méthode `_score()`.

```python
# Après le check TI exact (sha256), avant les heuristiques :
static_v2 = analyze_bytes(raw)
fuzzy_hit = _ti_fuzzy_lookup(static_v2)   # imphash exact, puis ssdeep, puis tlsh
if fuzzy_hit:
    return critical(family=fuzzy_hit["family"], kind=fuzzy_hit["kind"], ...)
```

Si pas de match TI fuzzy, le score Static-V2 contribue à hauteur de **15 %** dans l'agrégation finale (cf. [03 — pipeline](03-detection-pipeline.md)).

## Performance

| Opération | Temps moyen | Note |
|-----------|-------------|------|
| Multi-hash (sha1/md5/ssdeep/tlsh) | ~30 ms / Mo | I/O-bound |
| Parsing PE complet | ~50 ms | dépend de la taille du PE |
| `lookup_imphash` | <5 ms | index PostgreSQL |
| `lookup_fuzzy` (corpus < 100k) | ~200 ms | scan séquentiel + Python compare |

Pour un corpus > 100 k, indexer ssdeep par préfixe et utiliser TLSH directement (les bits 0-7 du hash sont des "buckets").

## Dégradation gracieuse

Si une lib native manque :

| Lib manquante | Effet |
|---------------|-------|
| `pefile` | Pas de parsing PE, fuzzy hashes seuls |
| `ssdeep` | Pas de hash ssdeep ; le détecteur tombe sur tlsh + imphash |
| `python-tlsh` | Idem ssdeep mais inverse |

Le détecteur **ne plante jamais** — c'est garanti par les `try/except` larges dans `_static_v2_run`.

## Sources & lectures

- **imphash** original : https://www.mandiant.com/resources/blog/tracking-malware-import-hashing
- **ssdeep** : https://ssdeep-project.github.io/ssdeep/
- **TLSH** : https://github.com/trendmicro/tlsh + paper IEEE 2013
- **EMBER feature set** (Endgame) : https://github.com/elastic/ember
- **MITRE ATT&CK Software Packing** : https://attack.mitre.org/techniques/T1027/002/
- **PE format reference** : https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- **Detect-It-Easy** (catalogue de signatures packers) : https://github.com/horsicq/Detect-It-Easy
- **Mandiant capa** (extraction de capacités) : https://github.com/mandiant/capa — roadmap intégration

## Suite

→ [06 — Système de modèles ML & ré-entraînement](06-modeles-ml.md)
