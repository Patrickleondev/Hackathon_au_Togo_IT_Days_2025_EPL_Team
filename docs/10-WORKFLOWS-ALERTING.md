# 10 - Workflows SOC, n8n et alerting continu

Cette page decrit l'integration optionnelle qui transforme GuardIAn en centre de commandes SOC connecte : GuardIAn collecte les signaux, n8n orchestre les workflows, un runner Nuclei autorise enrichit la surface externe, puis les alertes partent vers Discord, Telegram, WhatsApp ou un autre canal d'astreinte.

> Nuclei doit etre utilise uniquement sur des actifs que vous possedez ou pour lesquels vous avez une autorisation explicite. Gardez une allowlist stricte, des limites de frequence et des journaux d'audit.

## Objectif

- Surveiller continuellement les menaces GuardIAn et les resultats de scans autorises.
- Transformer les resultats techniques en digest lisible pour un analyste.
- Demander au chatbot GuardIAn de proposer les prochaines actions defensives.
- Notifier les equipes via les canaux deja utilises : Discord, Telegram, WhatsApp provider webhook.
- Garder l'integration facultative : le SOC fonctionne sans n8n.

## Architecture

```text
+----------------+        +----------------+        +-------------------+
| GuardIAn API   |<------>| n8n workflow   |<------>| Nuclei runner     |
| threats/chat   |        | orchestration  |        | allowlist only    |
+----------------+        +--------+-------+        +-------------------+
                                  |
                                  v
                    +-----------------------------+
                    | Discord / Telegram /        |
                    | WhatsApp provider webhook   |
                    +-----------------------------+
```

Le template fourni dans [integrations/n8n/guardian-soc-alerting-workflow.json](../integrations/n8n/guardian-soc-alerting-workflow.json) fait quatre choses :

1. Se connecte a GuardIAn via `/api/auth/login`.
2. Lit les menaces recentes via `/api/threats`.
3. Optionnellement, appelle un runner Nuclei interne via `POST /scan`.
4. Envoie le digest au chatbot GuardIAn via `/api/chat`, puis notifie les canaux d'astreinte.

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

## Runner Nuclei autorise

Le workflow n'execute pas Nuclei directement dans le conteneur n8n. Il attend un runner interne avec ce contrat minimal :

```http
POST /scan
Content-Type: application/json

{
  "targets": ["https://app.example.com"],
  "severity": ["medium", "high", "critical"]
}
```

Reponse attendue :

```json
{
  "findings": [
    {
      "template": "exposures/example",
      "severity": "high",
      "host": "https://app.example.com",
      "url": "https://app.example.com/.env",
      "matched": true
    }
  ]
}
```

Regles de securite recommandees pour ce runner :

- Refuser toute cible absente de l'allowlist.
- Limiter la cadence par cible et par utilisateur.
- Lancer Nuclei avec des templates valides et maintenus.
- Journaliser l'ID workflow, la cible, le timestamp, la severite et le statut.
- Ne jamais exposer le runner directement sur Internet.

Variables optionnelles :

```dotenv
NUCLEI_RUNNER_URL=http://runner.internal:8088
NUCLEI_TARGETS=https://app.example.com,https://api.example.com
```

Le noeud `Run authorized Nuclei scan` est desactive par defaut dans le template n8n. Activez-le seulement lorsque le runner et l'allowlist sont prets.

## Notifications

Les noeuds de notification sont desactives par defaut dans le workflow importe. Activez uniquement les canaux dont les variables sont configurees.

### Discord

Créer un webhook dans le salon SOC puis renseigner :

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

## Exploitation SOC

- Garder l'intervalle initial a 15 minutes.
- Envoyer les severites `critical` et `high` vers les canaux temps reel.
- Garder les severites `medium` dans le digest journalier si le volume augmente.
- Utiliser le resume GuardIAn comme point de depart, puis confirmer dans l'interface SOC avant toute action sensible.
- Archiver les executions n8n qui ont declenche une notification pour faciliter le post-mortem.

## Roadmap d'integration native

Cette integration reste volontairement externe. Les evolutions naturelles cote GuardIAn sont :

- endpoint `/api/workflows/events` pour recevoir les resultats n8n/Nuclei comme evenements SOC natifs ;
- timeline d'incident dans l'interface ;
- playbooks d'acknowledgement et d'escalade ;
- connecteurs Slack, Mattermost, email et SMS ;
- correlation entre Nuclei, Suricata, DGA, beaconing et menaces endpoint.
