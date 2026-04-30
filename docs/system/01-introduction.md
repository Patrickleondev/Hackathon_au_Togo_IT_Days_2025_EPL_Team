# 01 — Introduction : à quoi sert GuardIAn ?

## Le problème en 2026

Les antivirus classiques (signatures statiques) ne suffisent plus :

- **Polymorphisme** : un malware change quelques bytes → SHA-256 différent → signature inutile
- **Living-off-the-Land (LOLBins)** : `powershell.exe` lance du code malveillant — l'EXE est légitime
- **APT (Advanced Persistent Threats)** : groupes état-nation qui restent infiltrés des **mois**, contournent EDR
- **Zero-days** : aucune signature n'existe → détection statique = 0 %
- **Délais TI** : un nouveau malware met **72 h** en moyenne à apparaître dans VirusTotal — fenêtre d'or pour l'attaquant

## Ce que GuardIAn apporte

GuardIAn combine **6 couches** de détection. Si une couche rate, les autres rattrapent :

```
┌───────────────────────────────────────────────────────────────┐
│ ① TI EXACT          SHA-256 connu malveillant ?              │
│ ② TI FLOUE          imphash / ssdeep / tlsh similaires ?     │
│ ③ STATIQUE PROFOND  Packers ? Imports APT ? Sections WX ?    │
│ ④ HEURISTIQUE       Entropie, magic mismatch, patterns       │
│ ⑤ YARA              Règles communautaires (>10 000 dispo)    │
│ ⑥ ML ENSEMBLE       LightGBM + MalConv2 + CodeBERT (Phase E) │
└───────────────────────────────────────────────────────────────┘
                          ↓
                  Score agrégé pondéré
                          ↓
              Décision : critical / high / medium / low / safe
```

## Cas d'usage concrets

| Scénario | Couches qui détectent |
|----------|----------------------|
| Ransomware connu (LockBit, Conti) | ① ou ② immédiat |
| Variante zero-day d'une famille connue | ② (imphash/tlsh) |
| Sample packé avec UPX qu'on n'a jamais vu | ③ (packer) + ⑤ (YARA UPX) |
| Script PowerShell obfusqué | ⑥ (CodeBERT, Phase E) + ④ (patterns) |
| Document Office malveillant | ④ + ⑤ + ⑥ |
| Beaconing C2 silencieux | Phase C (réseau) |
| Process injection in-memory | Phase D (Sysmon EDR) |

## Pour qui ?

- **PME/Administrations** au Togo et en Afrique de l'Ouest qui n'ont pas les moyens d'un EDR commercial à 50 €/poste/an
- **SOC analystes** qui veulent un produit *open-source* hackable
- **Équipes DFIR** pour triage rapide post-incident
- **Étudiants/chercheurs** sécurité qui veulent un terrain de jeu réaliste

## Ce que GuardIAn n'est PAS

- ❌ Un EDR/XDR commercial complet (CrowdStrike, SentinelOne) — il en couvre ~60 % des fonctions
- ❌ Un sandbox dynamique (Cuckoo, ANY.RUN) — Phase D ajoutera l'ingestion Sysmon mais pas l'exécution
- ❌ Un produit "magique" — chaque couche a ses limites, l'efficacité vient de leur **empilement**

## Suite

→ [02 — Architecture globale](02-architecture-globale.md)
