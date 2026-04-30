# Sources & lectures recommandées

> Toutes les ressources qui ont nourri la conception de GuardIAn et qui te permettront d'approfondir.

## 📚 Livres / cours

- **Practical Malware Analysis** — Sikorski & Honig (No Starch Press, 2012). Bible pour comprendre PE + RE.
- **The IDA Pro Book, 2nd ed.** — Eagle (No Starch Press, 2011).
- **Windows Internals, 7th ed.** — Russinovich, Solomon, Ionescu, Yosifovich. Comprendre Sysmon/ETW.
- **Hands-On Machine Learning, 3rd ed.** — Géron (O'Reilly, 2023). LightGBM, ensembles, adversarial.
- **Black Hat Python, 2nd ed.** — Seitz (No Starch, 2021).

## 📄 Papers fondateurs

### Détection malware ML

- Anderson, Roth — *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models* (2018) — https://arxiv.org/abs/1804.04637
- Raff, Barker, Sylvester et al. — *Malware Detection by Eating a Whole EXE* (MalConv) (2017) — https://arxiv.org/abs/1710.09435
- Suciu, Coull, Johns — *Exploring Adversarial Examples in Malware Detection* (2019) — https://arxiv.org/abs/1810.08280

### NLP / Code

- Feng et al. — *CodeBERT: A Pre-Trained Model for Programming and Natural Languages* (2020) — https://arxiv.org/abs/2002.08155
- Clark et al. — *CANINE: Pre-training an Efficient Tokenization-Free Encoder for Language Representation* (2021) — https://arxiv.org/abs/2103.06874

### Streaming & drift

- Bifet, Gavalda — *Learning from Time-Changing Data with Adaptive Windowing* (ADWIN, 2007) — https://www.cs.upc.edu/~gavalda/papers/adwin06.pdf

### Hashes flous

- Kornblum — *Identifying almost identical files using context triggered piecewise hashing* (ssdeep, 2006) — https://dfrws.org/sites/default/files/session-files/paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf
- Oliver, Cheng, Chen — *TLSH — A Locality Sensitive Hash* (Trend Micro, 2013) — https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf

## 🛠️ Outils & frameworks

### Threat Intelligence

- **abuse.ch** (Bazaar, URLhaus, ThreatFox, Feodo, YARAify) — https://abuse.ch/
- **AlienVault OTX** — https://otx.alienvault.com/
- **AbuseIPDB** — https://www.abuseipdb.com/
- **MISP** — https://www.misp-project.org/ (TI partagée open-source)
- **OpenCTI** — https://www.filigran.io/en/products/opencti/

### Analyse statique

- **pefile** — https://github.com/erocarrera/pefile
- **lief** — https://github.com/lief-project/LIEF (alternative à pefile, multi-format)
- **capa** (FLARE) — https://github.com/mandiant/capa
- **Detect-It-Easy** — https://github.com/horsicq/Detect-It-Easy
- **YARA** — https://virustotal.github.io/yara/
- **YARA Rules community** — https://github.com/Yara-Rules/rules

### EDR / dynamique

- **Sysmon** — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- **Sysmon-modular** — https://github.com/olafhartong/sysmon-modular
- **PE-sieve, Hollows Hunter** — https://github.com/hasherezade
- **Velociraptor** — https://docs.velociraptor.app/

### Sigma / detection-as-code

- **pySigma** — https://github.com/SigmaHQ/pySigma
- **Sigma rules repo** — https://github.com/SigmaHQ/sigma

### ML / data

- **EMBER dataset** — https://github.com/elastic/ember
- **SOREL-20M** — https://github.com/sophos/SOREL-20M
- **Sophos Reversinglabs MOTIF** — https://github.com/sophos/sophos-malware-detection
- **river** (streaming ML) — https://riverml.xyz/

### Infrastructure / sécurité

- **Cosign / Sigstore** — https://docs.sigstore.dev/
- **HashiCorp Vault** — https://developer.hashicorp.com/vault
- **OWASP Top 10 2025** — https://owasp.org/www-project-top-ten/

## 🌐 MITRE / standards

- **MITRE ATT&CK** — https://attack.mitre.org/
- **MITRE D3FEND** — https://d3fend.mitre.org/
- **MITRE Engage** (déception) — https://engage.mitre.org/
- **STIX 2.1 / TAXII** — https://oasis-open.github.io/cti-documentation/
- **Microsoft PE format** — https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

## 🎤 Conférences / talks

- **DEF CON Malware Village** — https://malwarevillage.org/
- **VirusBulletin** — https://www.virusbulletin.com/
- **BlueHat IL** — https://www.bluehatil.com/
- **Black Hat / DEF CON** archives — https://www.youtube.com/@BlackHatOfficialYT
- **SANS DFIR Summit** — https://www.sans.org/cyber-security-summit/

## 📝 Blogs à suivre

- **Mandiant blog** — https://www.mandiant.com/resources/blog
- **CrowdStrike Adversary Universe** — https://www.crowdstrike.com/adversaries/
- **Microsoft Threat Intelligence** — https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/
- **Elastic Security Labs** — https://www.elastic.co/security-labs
- **Hexacorn** (RE) — https://www.hexacorn.com/blog/
- **VX-Underground** — https://www.vx-underground.org/

## 🎓 Cours en ligne (gratuits ou peu chers)

- **Fundamentals of Cybersecurity** (Coursera, IBM)
- **Open Security Training 2** — https://ost2.fyi/ (RE, exploitation)
- **PEN-200 / OSCP** (payant) — https://www.offsec.com/courses/pen-200/
- **TryHackMe — SOC Analyst path**
- **HackTheBox Academy — SOC Analyst path**

## 🇨🇮🇹🇬🇧🇫 Communautés africaines

- **AfricaHackon** (Kenya) — https://www.africahackon.com/
- **DjangoCon Africa** — https://2024.djangocon.africa/
- **PyCon Africa** — https://africa.pycon.org/
- **Togo IT Days** — toi-même (😉)

---

## Comment contribuer

Si tu trouves une ressource excellente, ouvre une PR sur ce fichier. Les sources doivent être :

- **Gratuites** ou très accessibles
- **Maintenues** récemment
- **Rigoureuses** (pas de "magie marketing")

→ Retour à l'[index documentation](00-README.md)
