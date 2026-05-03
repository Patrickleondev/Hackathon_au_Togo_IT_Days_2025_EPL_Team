# 08 - Installation pas a pas

Ce guide est la version courte et debutant-friendly. Pour le guide complet,
voir [../04-INSTALL.md](../04-INSTALL.md). Pour un VPS, voir
[../08-DEPLOYMENT.md](../08-DEPLOYMENT.md).

## 1. Prerequis

| Outil | Version | Pourquoi | Installation |
| --- | --- | --- | --- |
| Docker Desktop / Engine | 24+ | lancer la stack | <https://www.docker.com/products/docker-desktop> |
| Git | 2.30+ | cloner le projet | <https://git-scm.com/download> |
| Node.js | 20 LTS | dev frontend local | <https://nodejs.org/> |
| Python | 3.11+ | agent ou backend local | <https://www.python.org/downloads/> |
| VS Code | recent | edition du projet | <https://code.visualstudio.com/> |

Sur Windows, lancez Docker Desktop avant les commandes Docker.

## 2. Cloner le depot

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team
```

## 3. Creer le fichier d'environnement

```bash
cp infra/.env.example infra/.env
```

PowerShell :

```powershell
Copy-Item infra\.env.example infra\.env
```

Remplissez au minimum :

```ini
SECRET_KEY=<secret fort>
POSTGRES_USER=guardian
POSTGRES_PASSWORD=<mot de passe fort>
POSTGRES_DB=guardian
BOOTSTRAP_ADMIN_EMAIL=admin@guardian.local
BOOTSTRAP_ADMIN_PASSWORD=<mot de passe admin>
AGENT_ENROLLMENT_SECRET=<secret agent>
VITE_API_URL=http://localhost:8000
```

## 4. Lancer la stack

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

Verifier :

```bash
docker compose -f infra/docker-compose.yml ps
curl http://localhost:8000/api/health
```

Reponse attendue :

```json
{"status":"healthy"}
```

## 5. Ouvrir l'application

- Site public : <http://localhost:5173>
- Login SOC : <http://localhost:5173/login>
- Console SOC : <http://localhost:5173/app>
- API docs : <http://localhost:8000/docs>

Connectez-vous avec `BOOTSTRAP_ADMIN_EMAIL` et `BOOTSTRAP_ADMIN_PASSWORD`.

## 6. Tester le frontend

```bash
cd frontend
npm ci
npm run build
```

## 7. Tester une analyse de fichier

Connectez-vous d'abord via `/login`, puis utilisez la page `Analyze` de la
console SOC. En CLI, l'endpoint reel est :

```bash
curl -X POST http://localhost:8000/api/analyze/file \
  -H "Authorization: Bearer <token>" \
  -F "file=@sample.bin"
```

## 8. Voir les logs

```bash
docker compose -f infra/docker-compose.yml logs -f backend worker frontend
```

## 9. Arreter ou nettoyer

Arreter sans supprimer les donnees :

```bash
docker compose -f infra/docker-compose.yml down
```

Supprimer les volumes de developpement :

```bash
docker compose -f infra/docker-compose.yml down -v
```

## 10. Problemes frequents

| Probleme | Solution |
| --- | --- |
| Docker ne repond pas | lancer Docker Desktop ou verifier le service Docker |
| variable `POSTGRES_USER` manquante | creer `infra/.env` depuis `infra/.env.example` |
| API inaccessible | verifier `docker compose -f infra/docker-compose.yml logs backend` |
| login refuse | verifier les identifiants bootstrap dans `infra/.env` |
| frontend rouge sur l'API | verifier `VITE_API_URL=http://localhost:8000` |

## 11. Suite

- Installation complete : [../04-INSTALL.md](../04-INSTALL.md).
- VPS / production : [../08-DEPLOYMENT.md](../08-DEPLOYMENT.md).
- Operations : [../07-OPS.md](../07-OPS.md).
