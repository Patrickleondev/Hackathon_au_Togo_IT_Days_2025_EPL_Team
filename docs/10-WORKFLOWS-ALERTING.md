# 10 - Workflows SOC et alerting GuardIAn

Cette page decrit l'integration optionnelle qui transforme les alertes natives GuardIAn en boucle SOC continue : detection, digest, resume analyste, notification, puis suivi de l'intelligence de detection.

Nuclei et les scanners externes ne font pas partie de cette integration initiale. Ils restent une piste future, a brancher plus tard quand le coeur GuardIAn sera stable.

## Objectif

- Surveiller continuellement les alertes GuardIAn : endpoint, reseau, YARA, heuristiques, ML et threat intelligence.
- Ajouter un digest lisible pour un analyste avant l'escalade.
- Demander au chatbot GuardIAn de proposer les prochaines actions defensives.
- Notifier les equipes via Discord, Telegram, WhatsApp provider webhook ou un autre canal d'astreinte.
- Suivre l'etat des feeds, des regles YARA et de l'intelligence locale.
- Garder n8n facultatif : GuardIAn fonctionne sans workflow externe.

## Architecture

```text
+-----------------------+        +----------------------+        +-----------------------------+
| GuardIAn API          |------->| n8n SOC workflow     |------->| Discord / Telegram /        |
| alerts, intel, chat   |        | digest + escalation  |        | WhatsApp provider webhook   |
+-----------+-----------+        +----------+-----------+        +-----------------------------+
            |                               |
            v                               v
+-----------------------+        +----------------------+
| TI + YARA scheduler   |        | SOC operator actions |
| MalwareBazaar, etc.   |        | ack, triage, refresh |
+-----------------------+        +----------------------+
```

Le template [integrations/n8n/guardian-soc-alerting-workflow.json](../integrations/n8n/guardian-soc-alerting-workflow.json) fait trois choses :

1. Se connecte a GuardIAn via `/api/auth/login`.
2. Lit les alertes recentes via `/api/threats` et l'etat detection-intelligence via `/api/intel/stats`.
3. Envoie le digest au chatbot GuardIAn via `/api/chat`, puis notifie les canaux actives.

Une branche desactivee permet aussi de declencher `/api/intel/refresh` toutes les 6 heures, pour les environnements connectes ou l'equipe SOC veut piloter la synchronisation depuis n8n. Le backend GuardIAn possede deja son scheduler interne ; cette branche est donc un controle supplementaire, pas une obligation.

## Demarrage local

Copier les variables d'environnement puis generer les secrets :

```bash
cp infra/.env.example infra/.env
```

Ajouter au minimum :

```dotenv
N8N_ENCRYPTION_KEY=<openssl rand -hex 32>
N8N_GUARDIAN_API_URL=http://host.docker.internal:8000/api
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
WHATSAPP_WEBHOOK_URL=
```

Demarrer GuardIAn, puis n8n :

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.workflows.yml up -d
```

Ouvrir `http://localhost:5678`, creer le compte n8n local, puis importer le workflow JSON depuis `integrations/n8n/guardian-soc-alerting-workflow.json`.

## Demarrage VPS

Sur VPS, utilisez l'URL publique de l'API GuardIAn :

```dotenv
N8N_PROTOCOL=https
N8N_HOST=workflow.example.com
N8N_WEBHOOK_URL=https://workflow.example.com/
N8N_GUARDIAN_API_URL=https://guardian.example.com/api
N8N_ENCRYPTION_KEY=<secret fort>
```

Commandes :

```bash
docker compose -f infra/docker-compose.prod.yml up -d
docker compose -f infra/docker-compose.workflows.yml up -d
```

En production, proteger n8n derriere TLS, un mot de passe fort et idealement un VPN ou une restriction IP.

## Refresh detection-intelligence

GuardIAn a deja un scheduler backend qui rafraichit les feeds selon `INTEL_UPDATE_INTERVAL_HOURS`. Les sources configurees aujourd'hui couvrent :

- MalwareBazaar pour les hashes et metadonnees malware ;
- URLhaus pour URLs et domaines malveillants ;
- ThreatFox pour IOCs et familles ;
- Feodo Tracker pour C2 ;
- YARAify pour les regles YARA communautaires ;
- AbuseIPDB et OTX si les cles sont configurees.

Le workflow n8n lit `/api/intel/stats` a chaque digest pour afficher le nombre de hashes, indicateurs et regles YARA disponibles. La branche `Every 6 hours` est desactivee par defaut ; si elle est activee, elle appelle `POST /api/intel/refresh` avec un compte admin GuardIAn.

Bonnes pratiques :

- Activer la branche n8n seulement si l'instance a le droit de sortir vers Internet.
- Garder les cles abuse.ch, AbuseIPDB et OTX dans `infra/.env`, jamais dans le workflow JSON.
- Surveiller les statuts `last_runs` pour detecter un feed casse ou une cle expiree.
- Recharger le backend apres ajout de regles YARA locales pour recompiler le moteur.

## Notifications

Les noeuds de notification sont desactives par defaut dans le workflow importe. Activez uniquement les canaux dont les variables sont configurees.

### Discord

Creer un webhook dans le salon SOC puis renseigner :

```dotenv
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### Telegram

Creer un bot avec BotFather, recuperer l'identifiant du chat SOC, puis renseigner :

```dotenv
TELEGRAM_BOT_TOKEN=123456:token
TELEGRAM_CHAT_ID=-1001234567890
```

### WhatsApp

Utiliser un provider officiel ou un middleware interne qui expose un webhook HTTP. Le workflow envoie :

```json
{
  "source": "guardian-soc",
  "text": "digest SOC"
}
```

Configurer :

```dotenv
WHATSAPP_WEBHOOK_URL=https://provider.example.com/guardian-alerts
```

## Idees de modules GuardIAn vNext

Ces idees sont plus puissantes que brancher un scanner externe trop tot, parce qu'elles renforcent le coeur de detection GuardIAn.

### Detection Intelligence Center

- Vue SOC dediee aux sources : YARAify, MalwareBazaar, URLhaus, ThreatFox, Feodo, OTX, AbuseIPDB.
- Bouton admin `Refresh now` qui appelle `/api/intel/refresh`.
- Etat par feed : dernier succes, duree, volume ingere, erreurs, prochaine execution.
- Score de fraicheur global : `healthy`, `degraded`, `stale`, `offline`.

### RuleOps YARA

- Catalogue des regles YARA locales et communautaires.
- Compilation test avant activation.
- Versioning des regles, rollback et activation par profil : strict, balanced, permissive.
- Mesure faux positifs : si une regle declenche trop de dismiss, elle passe en observation.

### Detection Algorithms Plus

- Sigma pour les logs Windows/Sysmon et Linux auditd.
- JA3/JA4 et Suricata/Zeek pour reseau.
- Fuzzy matching ssdeep/TLSH/imphash avec seuils adaptatifs.
- Ransomware canary files et detection d'ecriture massive.
- Drift monitoring ML : baisse de confiance, hausse de verdicts low-confidence, familles inconnues.

### Connected Sync Mode

- Mode connecte : refresh automatique TI/YARA, verification de versions modele, sync des politiques SOC.
- Mode deconnecte : cache local signe, imports offline de packs YARA/TI/modeles.
- Journal d'audit de chaque sync : source, hash du bundle, signature, resultat.

### Auto-training Control Plane

Le systeme d'auto-entrainement existe deja comme base. Le module suivant doit surtout le rendre gouvernable :

- file d'attente `training_candidates` depuis faux positifs, vrais positifs confirmes et low-confidence ;
- validation analyste avant inclusion dans le dataset ;
- entrainement hors production, export modele signe ;
- evaluation avant promotion : precision, recall, faux positifs, regression tests ;
- deploiement canary par groupe d'agents avant activation globale.

## Roadmap future

- Endpoint `/api/workflows/events` pour historiser les actions n8n et les escalades.
- Timeline d'incident dans l'interface SOC.
- Playbooks d'acknowledgement, d'escalade et de fermeture d'alerte.
- Connecteurs Slack, Mattermost, email et SMS.
- Plus tard seulement : integration Nuclei ou scanner externe, separee du workflow d'alertes GuardIAn.
