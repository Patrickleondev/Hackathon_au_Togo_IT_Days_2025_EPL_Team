"""Bilingual FAQ knowledge base for GuardIAn.

Curated from ``docs/system/09-faq-glossaire.md`` and the project README.
Each entry is structured so it can serve three purposes:

1. Power a static **FAQ page** (frontend ``/faq``).
2. Be retrieved by simple keyword scoring to answer a user message
   without an LLM (offline / free fallback).
3. Be passed as **grounding context** to an LLM provider when one is
   configured, so answers stay factual to the project.

Keep this file dependency-free and pure-data — it is imported eagerly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

Lang = Literal["fr", "en"]


@dataclass(frozen=True, slots=True)
class FAQEntry:
    """One FAQ item, available in both languages."""

    id: str
    category: str  # "general" | "detection" | "ml" | "deployment" | "team"
    question_fr: str
    question_en: str
    answer_fr: str
    answer_en: str
    keywords: tuple[str, ...] = field(default_factory=tuple)

    def question(self, lang: Lang) -> str:
        return self.question_en if lang == "en" else self.question_fr

    def answer(self, lang: Lang) -> str:
        return self.answer_en if lang == "en" else self.answer_fr


# ---------------------------------------------------------------------------
# Suggested prompts shown as chips in the chat widget.
# ---------------------------------------------------------------------------
SUGGESTIONS: dict[Lang, tuple[str, ...]] = {
    "fr": (
        "Comment GuardIAn détecte un ransomware ?",
        "Quelle est la différence avec un antivirus classique ?",
        "Comment installer l'agent Windows ?",
        "Quelles sont les phases du projet ?",
        "GuardIAn fonctionne-t-il hors-ligne ?",
        "Qui est l'équipe EPL ?",
    ),
    "en": (
        "How does GuardIAn detect ransomware?",
        "How is it different from a regular antivirus?",
        "How do I install the Windows agent?",
        "What are the project phases?",
        "Does GuardIAn work offline?",
        "Who is the EPL team?",
    ),
}


# ---------------------------------------------------------------------------
# FAQ catalog.
# ---------------------------------------------------------------------------
FAQ: tuple[FAQEntry, ...] = (
    FAQEntry(
        id="what-is-guardian",
        category="general",
        question_fr="Qu'est-ce que GuardIAn ?",
        question_en="What is GuardIAn?",
        answer_fr=(
            "GuardIAn est un **antivirus / EDR open-source de nouvelle génération** "
            "conçu pour détecter les ransomwares connus *et* les variantes inconnues "
            "(zero-day). Il combine 7 flux de Threat Intelligence rafraîchis toutes "
            "les 6 h, une analyse statique multi-couches (hash, PE, packers, YARA), "
            "des modèles d'IA (LightGBM + ONNX + transformers) et — en Phase C — un "
            "moteur réseau (DGA, beaconing, JA3/JA4, Suricata/Zeek)."
        ),
        answer_en=(
            "GuardIAn is a **next-generation open-source antivirus / EDR** built to "
            "detect known ransomware *and* unknown variants (zero-day). It combines "
            "7 Threat Intelligence feeds refreshed every 6 hours, multi-layer "
            "static analysis (hash, PE, packers, YARA), AI models "
            "(LightGBM + ONNX + transformers), and — in Phase C — a network engine "
            "(DGA, beaconing, JA3/JA4, Suricata/Zeek)."
        ),
        keywords=("guardian", "what", "qu'est", "projet", "définition", "intro"),
    ),
    FAQEntry(
        id="why-six-layers",
        category="detection",
        question_fr="Pourquoi 6 couches de détection ?",
        question_en="Why 6 detection layers?",
        answer_fr=(
            "Aucune couche n'est parfaite. Un attaquant peut contourner UNE couche, "
            "plus difficilement TROIS, quasiment jamais SIX. C'est le principe de "
            "**défense en profondeur**. Les couches actuelles : (1) hashes exacts, "
            "(2) hashes flous (ssdeep/TLSH), (3) analyse PE, (4) règles YARA, "
            "(5) ML (LightGBM/ONNX), (6) Threat Intelligence."
        ),
        answer_en=(
            "No single layer is perfect. An attacker can bypass ONE layer, hardly "
            "THREE, almost never SIX. This is **defence in depth**. Current layers: "
            "(1) exact hashes, (2) fuzzy hashes (ssdeep/TLSH), (3) PE analysis, "
            "(4) YARA rules, (5) ML (LightGBM/ONNX), (6) Threat Intelligence."
        ),
        keywords=("layer", "couche", "détection", "detection", "defense", "depth"),
    ),
    FAQEntry(
        id="vs-classic-av",
        category="detection",
        question_fr="Quelle différence avec un antivirus classique ?",
        question_en="How is it different from a regular antivirus?",
        answer_fr=(
            "Les AV grand public (Defender, Kaspersky) excellent en signatures et "
            "heuristiques mais ne croisent pas avec les feeds TI live, n'utilisent "
            "pas ssdeep/TLSH à grande échelle, et leurs modèles ML sont fermés. "
            "GuardIAn est un **EDR open-source** : tout est inspectable, le SOC "
            "peut ajouter ses propres règles YARA / Sigma, ré-entraîner les "
            "modèles, et brancher ses propres feeds TI."
        ),
        answer_en=(
            "Consumer AVs (Defender, Kaspersky) are strong on signatures and "
            "heuristics but do not cross-reference live TI feeds, do not use "
            "ssdeep/TLSH at scale, and their ML models are closed-source. GuardIAn "
            "is an **open-source EDR**: everything is auditable, the SOC team can "
            "ship their own YARA / Sigma rules, retrain models, and plug in their "
            "own TI feeds."
        ),
        keywords=("antivirus", "av", "defender", "kaspersky", "edr", "different", "différence"),
    ),
    FAQEntry(
        id="false-positives",
        category="detection",
        question_fr="Comment minimiser les faux positifs ?",
        question_en="How do I minimise false positives?",
        answer_fr=(
            "1) Laissez tourner Phase A (TI exact) au moins 24 h pour peupler la "
            "base. 2) Ajustez `THRESHOLD_LOW/MEDIUM/HIGH` dans `infra/.env`. "
            "3) Enrôlez les binaires Authenticode légitimes (allowlist). "
            "4) Phase F apporte de l'active learning + détection de drift qui "
            "corrigent les biais en continu."
        ),
        answer_en=(
            "1) Let Phase A (exact TI) run at least 24h to populate the database. "
            "2) Tune `THRESHOLD_LOW/MEDIUM/HIGH` in `infra/.env`. "
            "3) Allow-list signed Authenticode binaries. "
            "4) Phase F adds active learning + drift detection that correct biases "
            "continuously."
        ),
        keywords=("false positive", "faux positif", "fpr", "tuning", "threshold"),
    ),
    FAQEntry(
        id="how-detects-ransomware",
        category="detection",
        question_fr="Comment GuardIAn détecte un ransomware ?",
        question_en="How does GuardIAn detect a ransomware?",
        answer_fr=(
            "Sur un fichier : (1) hash SHA-256 contre la base TI → match immédiat ; "
            "(2) ssdeep/TLSH → variantes proches d'une famille connue ; "
            "(3) parsing PE → packers, sections WX, TLS callbacks ; "
            "(4) YARA → patterns de code malveillant ; "
            "(5) ML LightGBM sur features statiques + ONNX deep models ; "
            "(6) corrélation TI sur URLs/IPs intégrées au binaire. "
            "Le score final combine les 6 sources avec des poids appris."
        ),
        answer_en=(
            "For a file: (1) SHA-256 hash against the TI database → instant match; "
            "(2) ssdeep/TLSH → variants close to a known family; "
            "(3) PE parsing → packers, WX sections, TLS callbacks; "
            "(4) YARA → malicious code patterns; "
            "(5) ML LightGBM on static features + ONNX deep models; "
            "(6) TI correlation on URLs/IPs embedded in the binary. "
            "The final score combines all 6 sources with learned weights."
        ),
        keywords=("detect", "détect", "ransomware", "malware", "scan", "analyse"),
    ),
    FAQEntry(
        id="phases",
        category="general",
        question_fr="Quelles sont les phases du projet ?",
        question_en="What are the project phases?",
        answer_fr=(
            "**A** ✅ Threat Intelligence (7 feeds, 6 h). "
            "**B** ✅ Static-V2 (multi-hash, PE deep, packers). "
            "**C** ✅ Réseau-V2 (DGA, beaconing FFT, JA3/JA4, Suricata/Zeek). "
            "**D** 🔜 Comportemental APT (Sysmon, ATT&CK, canary, Sigma). "
            "**E** 🔜 ML-V2 (EMBER, MalConv2, CodeBERT, ensembles). "
            "**F** 🔜 MLOps (active learning, drift ADWIN, registry signé)."
        ),
        answer_en=(
            "**A** ✅ Threat Intelligence (7 feeds, 6h). "
            "**B** ✅ Static-V2 (multi-hash, PE deep, packers). "
            "**C** ✅ Network-V2 (DGA, FFT beaconing, JA3/JA4, Suricata/Zeek). "
            "**D** 🔜 Behavioural APT (Sysmon, ATT&CK, canary, Sigma). "
            "**E** 🔜 ML-V2 (EMBER, MalConv2, CodeBERT, ensembles). "
            "**F** 🔜 MLOps (active learning, ADWIN drift, signed registry)."
        ),
        keywords=("phase", "roadmap", "étape", "stage"),
    ),
    FAQEntry(
        id="install-agent",
        category="deployment",
        question_fr="Comment installer l'agent Windows ?",
        question_en="How do I install the Windows agent?",
        answer_fr=(
            "1) Démarrer le backend (`docker compose up` dans `infra/`). "
            "2) Récupérer le secret d'enrôlement (`AGENT_ENROLLMENT_SECRET` du "
            "`.env`). 3) Côté poste, lancer `agent.exe enroll --server "
            "https://soc.local --secret <secret>`. 4) L'agent s'enregistre via "
            "`POST /api/agents/enroll`, reçoit un JWT longue durée et démarre les "
            "heartbeats. Détails complets dans `docs/system/07-agent-windows.md`."
        ),
        answer_en=(
            "1) Start the backend (`docker compose up` in `infra/`). "
            "2) Grab the enrolment secret (`AGENT_ENROLLMENT_SECRET` from `.env`). "
            "3) On the endpoint run `agent.exe enroll --server https://soc.local "
            "--secret <secret>`. 4) The agent registers via `POST /api/agents/"
            "enroll`, receives a long-lived JWT and starts heartbeats. Full "
            "details in `docs/system/07-agent-windows.md`."
        ),
        keywords=("install", "installer", "agent", "windows", "enroll", "déploiement"),
    ),
    FAQEntry(
        id="works-offline",
        category="deployment",
        question_fr="GuardIAn fonctionne-t-il hors-ligne ?",
        question_en="Does GuardIAn work offline?",
        answer_fr=(
            "Oui pour la **détection** : modèles ML, YARA, hashes locaux "
            "fonctionnent sans Internet. Les **feeds TI** nécessitent une "
            "connexion sortante toutes les 6 h, mais l'AV continue de protéger "
            "avec la dernière base téléchargée. Le mode `INTEL_ENABLED=false` "
            "désactive tout appel sortant."
        ),
        answer_en=(
            "Yes for **detection**: ML models, YARA, local hashes work without "
            "Internet. **TI feeds** need outbound connectivity every 6h, but the "
            "AV keeps protecting with the last downloaded database. Setting "
            "`INTEL_ENABLED=false` disables all outbound calls."
        ),
        keywords=("offline", "hors-ligne", "internet", "déconnecté", "air-gap"),
    ),
    FAQEntry(
        id="gpu-required",
        category="deployment",
        question_fr="Faut-il un GPU ?",
        question_en="Is a GPU required?",
        answer_fr=(
            "Pas pour l'inférence : LightGBM + ONNX Runtime tournent en CPU "
            "(< 50 ms par fichier sur un Core i5). Pour l'**entraînement** Phase E "
            "(MalConv2, CodeBERT), un GPU aide ; Google Colab gratuit (T4) suffit."
        ),
        answer_en=(
            "Not for inference: LightGBM + ONNX Runtime run on CPU (< 50 ms per "
            "file on a Core i5). For **training** in Phase E (MalConv2, CodeBERT) "
            "a GPU helps; free Google Colab (T4) is enough."
        ),
        keywords=("gpu", "cuda", "training", "entraînement", "colab", "performance"),
    ),
    FAQEntry(
        id="rgpd",
        category="deployment",
        question_fr="Les données utilisateurs sont-elles RGPD-compliant ?",
        question_en="Is user data GDPR-compliant?",
        answer_fr=(
            "Les IOC publics (hashes, IPs, domaines) ne sont pas des données "
            "personnelles. Les pulses OTX peuvent contenir des emails dans les "
            "indicateurs — ils sont stockés tels quels mais pas exposés en clair. "
            "Le chatbot **ne mémorise pas** les conversations et n'envoie aucun "
            "contenu à un LLM tiers si aucune clé n'est configurée. À auditer "
            "avant production en UE."
        ),
        answer_en=(
            "Public IOCs (hashes, IPs, domains) are not personal data. OTX pulses "
            "can contain emails in indicators — stored as-is but not exposed in "
            "plaintext. The chatbot **does not store** conversations and sends "
            "nothing to a third-party LLM if no API key is configured. Audit "
            "before EU production."
        ),
        keywords=("rgpd", "gdpr", "privacy", "vie privée", "data", "données"),
    ),
    FAQEntry(
        id="team",
        category="team",
        question_fr="Qui est l'équipe EPL ?",
        question_en="Who is the EPL team?",
        answer_fr=(
            "Une équipe d'étudiants de l'**École Polytechnique de Lomé** (Togo) "
            "participant au **Hackathon Togo IT Days 2025**. Le projet est "
            "open-source sous licence Apache-2.0 et conçu pour être réutilisé "
            "par les CERT et SOC d'Afrique de l'Ouest. Contact : voir page "
            "« Contact »."
        ),
        answer_en=(
            "A team of students from **École Polytechnique de Lomé** (Togo) "
            "competing in the **Togo IT Days 2025 Hackathon**. The project is "
            "open-source under Apache-2.0 and designed to be reused by CERTs "
            "and SOCs in West Africa. Contact: see the « Contact » page."
        ),
        keywords=("team", "équipe", "epl", "togo", "lomé", "hackathon", "auteur"),
    ),
    FAQEntry(
        id="languages-supported",
        category="general",
        question_fr="Quelles langues sont supportées ?",
        question_en="Which languages are supported?",
        answer_fr=(
            "L'interface est disponible en **français** et **anglais**. Le "
            "chatbot répond dans la langue détectée du message. Le code et les "
            "logs internes restent en anglais."
        ),
        answer_en=(
            "The UI is available in **French** and **English**. The chatbot "
            "replies in the language detected from your message. Code and "
            "internal logs stay in English."
        ),
        keywords=("language", "langue", "i18n", "français", "english", "translation"),
    ),
    FAQEntry(
        id="open-source",
        category="general",
        question_fr="GuardIAn est-il open-source ?",
        question_en="Is GuardIAn open-source?",
        answer_fr=(
            "Oui, sous licence **Apache-2.0**. Code, modèles, règles YARA, "
            "documentation : tout est sur GitHub. Vous pouvez forker, contribuer "
            "et déployer en production gratuitement."
        ),
        answer_en=(
            "Yes, under the **Apache-2.0** license. Code, models, YARA rules, "
            "docs: everything is on GitHub. You can fork, contribute and deploy "
            "to production for free."
        ),
        keywords=("open source", "github", "license", "licence", "apache"),
    ),
    FAQEntry(
        id="llm-integration",
        category="general",
        question_fr="Le chatbot utilise-t-il une IA ?",
        question_en="Does the chatbot use an AI?",
        answer_fr=(
            "Par défaut, le chatbot répond depuis cette base de connaissances "
            "locale (aucun appel externe, aucune fuite de données). Si "
            "l'opérateur configure une clé API (`LLM_PROVIDER` + `LLM_API_KEY`), "
            "le chatbot peut router les questions hors-FAQ vers Anthropic Claude, "
            "OpenAI, Mistral, OpenRouter ou un Ollama local. Les réponses LLM "
            "sont *grounded* sur la documentation GuardIAn."
        ),
        answer_en=(
            "By default the chatbot answers from this local knowledge base (no "
            "external call, no data leaves the server). If the operator sets up "
            "an API key (`LLM_PROVIDER` + `LLM_API_KEY`), out-of-FAQ questions "
            "can be routed to Anthropic Claude, OpenAI, Mistral, OpenRouter or a "
            "local Ollama. LLM answers are *grounded* on GuardIAn documentation."
        ),
        keywords=("ai", "ia", "llm", "claude", "openai", "chatbot", "gpt"),
    ),
)


def get_faq(lang: Lang = "fr") -> list[dict]:
    """Return the FAQ catalog as plain dicts in the requested language."""
    return [
        {
            "id": e.id,
            "category": e.category,
            "question": e.question(lang),
            "answer": e.answer(lang),
        }
        for e in FAQ
    ]


def iter_faq() -> Iterable[FAQEntry]:
    return iter(FAQ)
