# 08 — Déploiement production, VPS et exploitation

Ce guide couvre le déploiement de GuardIAn sur un serveur Linux, un VPS ou une
machine on-premise. Pour une installation locale de développement, voir
[04-INSTALL.md](04-INSTALL.md).

## 1. Scénarios de déploiement

| Scénario | Recommandation | Ports publics |
| --- | --- | --- |
| Démo locale | `infra/docker-compose.yml` | 5173, 8000 |
| VPS public | `infra/docker-compose.prod.yml` + Nginx | 80, 443 |
| Réseau interne entreprise | Compose prod derrière reverse proxy interne | 443 |
| Grand parc (> 2000 endpoints) | Kubernetes ou services managés | selon architecture |

La production ne doit pas exposer PostgreSQL (`5432`) ni Redis (`6379`). Ces
services restent dans le réseau Docker interne.

## 2. Prérequis serveur

### 2.1 Ressources recommandées

| Taille | CPU | RAM | Disque | Notes |
| --- | ---: | ---: | ---: | --- |
| Démo VPS | 2 vCPU | 4 GB | 40 GB SSD | quelques agents |
| PME | 4 vCPU | 8 GB | 100 GB SSD | 10 à 200 agents |
| Moyenne entreprise | 8 vCPU | 16 GB | 500 GB NVMe | 200 à 2000 agents |

Prévoyez plus de disque si vous conservez les uploads, quarantaines ou flux de
threat intelligence sur plusieurs mois.

### 2.2 OS supportés

| OS | Statut | Notes |
| --- | --- | --- |
| Ubuntu 22.04 / 24.04 LTS | recommandé | cible principale |
| Debian 12 | supporté | proche Ubuntu |
| Rocky/RHEL 9 | supporté | tester les paquets système |
| Windows Server + Docker Desktop | possible | moins recommandé en production |

### 2.3 Logiciels à installer sur le serveur

- Docker Engine 24+
- Docker Compose plugin v2.20+
- Git
- OpenSSL
- Un pare-feu système (`ufw`, `firewalld` ou équivalent)

Vous n'avez pas besoin d'installer Node, Python, PostgreSQL ou Redis sur l'hôte
si vous utilisez Docker Compose.

## 3. Préparer le VPS

Exemple Ubuntu/Debian :

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssl ufw
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker
docker version
docker compose version
```

Pare-feu minimal :

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

Si l'API doit être accessible uniquement depuis un VPN ou un réseau interne,
n'ouvrez pas 80/443 publiquement : placez Nginx derrière votre reverse proxy ou
votre tunnel privé.

## 4. Cloner et configurer

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team
cp infra/.env.example infra/.env
nano infra/.env
```

Variables critiques :

```ini
APP_ENV=prod
APP_VERSION=2.0.0
SECRET_KEY=<openssl rand -hex 32>
JWT_ACCESS_TTL_MINUTES=60
JWT_AGENT_TTL_DAYS=30

POSTGRES_USER=guardian
POSTGRES_PASSWORD=<openssl rand -base64 24>
POSTGRES_DB=guardian

BOOTSTRAP_ADMIN_EMAIL=admin@votre-domaine.tg
BOOTSTRAP_ADMIN_PASSWORD=<mot de passe fort>
AGENT_ENROLLMENT_SECRET=<openssl rand -hex 32>

CORS_ORIGINS=["https://soc.votre-domaine.tg"]
VITE_API_URL=https://soc.votre-domaine.tg
```

Threat intelligence optionnelle :

```ini
ABUSE_CH_AUTH_KEY=<cle abuse.ch>
ABUSEIPDB_API_KEY=
INTEL_ABUSEIPDB_ENABLED=false
OTX_API_KEY=
INTEL_OTX_ENABLED=false
```

Assistant optionnel via LLM :

```ini
LLM_PROVIDER=none
LLM_API_KEY=
LLM_MODEL=
```

Gardez `LLM_PROVIDER=none` si vous voulez que le chat réponde uniquement depuis
la base de connaissances locale.

## 5. DNS et TLS

Créez un enregistrement DNS `A` vers l'IP du VPS, par exemple :

```text
soc.votre-domaine.tg -> 203.0.113.10
```

Pour Let's Encrypt, vous pouvez générer les certificats sur l'hôte puis les
monter dans `infra/nginx/certs` :

```bash
sudo apt-get install -y certbot
sudo certbot certonly --standalone -d soc.votre-domaine.tg
mkdir -p infra/nginx/certs
sudo cp /etc/letsencrypt/live/soc.votre-domaine.tg/fullchain.pem infra/nginx/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/soc.votre-domaine.tg/privkey.pem infra/nginx/certs/privkey.pem
sudo chown -R $USER:$USER infra/nginx/certs
```

Pour un test sans DNS public :

```bash
mkdir -p infra/nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout infra/nginx/certs/privkey.pem \
  -out infra/nginx/certs/fullchain.pem \
  -subj "/CN=soc.local"
```

Vérifiez ensuite la configuration Nginx dans `infra/nginx/` selon votre domaine.

## 6. Build et démarrage production

Depuis la racine du dépôt :

```bash
docker compose -f infra/docker-compose.prod.yml config
docker compose -f infra/docker-compose.prod.yml up -d --build
docker compose -f infra/docker-compose.prod.yml ps
```

Si Docker Compose indique qu'une variable est manquante, corrigez `infra/.env`.

Logs utiles :

```bash
docker compose -f infra/docker-compose.prod.yml logs -f backend worker nginx
```

Healthcheck :

```bash
curl -k https://soc.votre-domaine.tg/api/health
```

La réponse attendue contient `"status":"healthy"`.

## 7. Premier démarrage applicatif

1. Ouvrez `https://soc.votre-domaine.tg/login`.
2. Connectez-vous avec `BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD`.
3. Changez le mot de passe bootstrap dès que possible.
4. Vérifiez `/app`, `/app/network`, `/app/scans` et le terminal SOC flottant.
5. Entraînez ou montez les modèles si `detector_ready=false`.

Entraînement modèle :

```bash
docker compose -f infra/docker-compose.prod.yml exec backend \
  python -m scripts.train_detector
docker compose -f infra/docker-compose.prod.yml restart backend worker
```

## 8. Déployer des agents endpoints

Les agents doivent joindre l'URL publique ou interne du backend :

```text
BACKEND_URL=https://soc.votre-domaine.tg
AGENT_ENROLLMENT_SECRET=<même valeur que dans infra/.env>
```

Flux réseau minimal agent -> serveur :

| Direction            |    Port | Usage                                                                |
| -------------------- | ------: | -------------------------------------------------------------------- |
| agent vers serveur   | 443/tcp | enrollement, heartbeat, upload d'échantillons, événements réseau     |

Voir [05-AGENT-WINDOWS.md](05-AGENT-WINDOWS.md) pour le packaging Windows.

## 9. Sauvegardes

PostgreSQL est la source de vérité. Exemple de sauvegarde :

```bash
mkdir -p backups
docker compose -f infra/docker-compose.prod.yml exec -T db \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > backups/guardian-$(date +%F).sql.gz
```

Sauvegardez aussi le volume `guardian_data` si vous conservez :

- modèles entraînés ;
- uploads ;
- fichiers en quarantaine ;
- règles YARA personnalisées.

## 10. Mise à jour applicative

```bash
git pull
docker compose -f infra/docker-compose.prod.yml build
docker compose -f infra/docker-compose.prod.yml up -d
docker compose -f infra/docker-compose.prod.yml ps
```

Après modification des variables d'environnement :

```bash
docker compose -f infra/docker-compose.prod.yml up -d --force-recreate
```

## 11. Supervision minimale

Commandes utiles :

```bash
docker compose -f infra/docker-compose.prod.yml ps
docker compose -f infra/docker-compose.prod.yml logs --tail=100 backend
docker compose -f infra/docker-compose.prod.yml logs --tail=100 worker
docker stats
```

Workflow SOC optionnel :

```bash
docker compose -f infra/docker-compose.workflows.yml ps
docker compose -f infra/docker-compose.workflows.yml logs --tail=100 n8n
```

Endpoints utiles :

| Endpoint | Rôle |
| --- | --- |
| `/api/health` | backend vivant |
| `/api/status` | métriques système, agents, détecteur ML |
| `/api/stats` | résumé menaces |
| `/api/network/stats` | télémétrie réseau |
| `/api/chat/provider` | état du chatbot/LLM |

## 12. Durcissement production

- Restreindre SSH à votre IP ou à un VPN.
- Activer `ufw` ou `firewalld`.
- Ne pas exposer PostgreSQL/Redis hors Docker.
- Changer le mot de passe bootstrap après la première connexion.
- Utiliser des certificats TLS valides.
- Mettre `CORS_ORIGINS` au domaine réel uniquement.
- Générer `SECRET_KEY`, `POSTGRES_PASSWORD` et `AGENT_ENROLLMENT_SECRET` avec des valeurs fortes.
- Sauvegarder PostgreSQL quotidiennement vers un stockage externe.
- Surveiller l'espace disque de `/var/lib/docker` et du volume `guardian_data`.
- Garder `LLM_PROVIDER=none` si aucune clé LLM n'est officiellement autorisée.
- Si n8n est active, proteger l'interface par TLS, mot de passe fort, VPN ou restriction IP.
- Garder les workflows n8n limites aux endpoints GuardIAn tant que les connecteurs externes ne sont pas valides.

## 13. Dépannage VPS

| Symptôme | Cause probable | Correction |
| --- | --- | --- |
| `required variable POSTGRES_USER is missing` | `infra/.env` absent/incomplet | copier `.env.example`, remplir les variables |
| `dockerDesktopLinuxEngine` introuvable | Docker Desktop non lancé sur Windows | lancer Docker Desktop |
| Nginx démarre mais HTTPS échoue | certificats absents ou mauvais nom | vérifier `infra/nginx/certs/fullchain.pem` et `privkey.pem` |
| `/api/health` OK mais login KO | mauvais bootstrap ou DB déjà initialisée | vérifier logs backend et comptes existants |
| `detector_ready=false` | modèle non entraîné | lancer `scripts.train_detector` |
| Agents ne s'enrôlent pas | secret différent ou URL invalide | vérifier `AGENT_ENROLLMENT_SECRET` et `BACKEND_URL` |
| Frontend appelle localhost en production | `VITE_API_URL` mal réglé au build | mettre `VITE_API_URL=https://domaine` puis rebuild frontend |
| 413 upload trop gros | limite Nginx ou `MAX_UPLOAD_MB` | augmenter les deux valeurs |
| n8n ne demarre pas | `N8N_ENCRYPTION_KEY` absent | generer une valeur forte dans `infra/.env` |
| workflow sans notifications | webhook Discord/Telegram/WhatsApp vide | configurer le canal voulu ou desactiver le noeud correspondant |
| refresh TI/YARA refuse | compte non admin ou token expire | verifier le role du compte utilise par n8n |

## 14. Checklist de production

- `docker compose -f infra/docker-compose.prod.yml config` passe.
- `docker compose -f infra/docker-compose.prod.yml ps` montre les services en marche.
- `https://<domaine>/api/health` répond.
- `/login` fonctionne avec le compte bootstrap.
- `/app` affiche les métriques SOC.
- `/app/network` affiche une réponse ou une erreur claire.
- Le terminal flottant SOC répond.
- Si active, n8n importe [integrations/n8n/guardian-soc-alerting-workflow.json](../integrations/n8n/guardian-soc-alerting-workflow.json).
- Les sauvegardes PostgreSQL sont planifiées.
- Les ports 5432 et 6379 ne sont pas exposés publiquement.
