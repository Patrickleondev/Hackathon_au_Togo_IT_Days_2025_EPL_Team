import { Cpu, Database, Server, Shield, Workflow } from 'lucide-react'

export default function Architecture() {
  return (
    <div className="max-w-6xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">Architecture</h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          Une plateforme distribuée, conteneurisée, conçue pour passer à l'échelle d'un parc de plusieurs milliers d'endpoints.
        </p>
      </div>

      {/* Topology diagram */}
      <section className="rounded-xl bg-slate-900 border border-slate-800 p-8 mb-16">
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <Workflow className="text-brand-400" /> Topologie générale
        </h2>
        <div className="grid md:grid-cols-3 gap-6">
          <div className="rounded-lg bg-slate-950 border border-slate-800 p-5">
            <Cpu className="w-8 h-8 text-emerald-400 mb-3" />
            <h3 className="font-semibold mb-2">Endpoints (1 → N)</h3>
            <ul className="text-sm text-slate-400 space-y-1">
              <li>• Agent Python / PyInstaller</li>
              <li>• Watchdog filesystem</li>
              <li>• Heuristiques locales</li>
              <li>• Heartbeat HTTPS+JWT</li>
            </ul>
          </div>
          <div className="rounded-lg bg-slate-950 border border-brand-700 p-5">
            <Server className="w-8 h-8 text-brand-400 mb-3" />
            <h3 className="font-semibold mb-2">Backend SOC</h3>
            <ul className="text-sm text-slate-400 space-y-1">
              <li>• FastAPI 0.115 (async)</li>
              <li>• Détecteur Heuristique + ML + YARA</li>
              <li>• Worker RQ pour scans longs</li>
              <li>• Auth JWT 2 scopes (user/agent)</li>
            </ul>
          </div>
          <div className="rounded-lg bg-slate-950 border border-slate-800 p-5">
            <Database className="w-8 h-8 text-purple-400 mb-3" />
            <h3 className="font-semibold mb-2">Stockage</h3>
            <ul className="text-sm text-slate-400 space-y-1">
              <li>• PostgreSQL 16 (durable)</li>
              <li>• Redis 7 (jobs queue)</li>
              <li>• Volume Docker `guardian_data`</li>
              <li>• Quarantaine isolée</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Mermaid-style ASCII diagram */}
      <section className="rounded-xl bg-slate-950 border border-slate-800 p-8 mb-16 overflow-x-auto">
        <h2 className="text-2xl font-bold mb-6">Flux de données</h2>
        <pre className="text-xs md:text-sm text-slate-300 leading-relaxed">{`
  ┌──────────────┐    HTTPS+JWT     ┌──────────────────────────┐
  │  Endpoint    │ ───────────────► │   FastAPI Backend        │
  │  Agent       │                  │  ┌────────────────────┐  │
  │ (watchdog)   │ ◄─── 200 OK ──── │  │ /analyze/agent-file│  │
  └──────────────┘                  │  └─────────┬──────────┘  │
                                    │            ▼             │
                                    │  ┌────────────────────┐  │
                                    │  │ Unified Detector   │  │
                                    │  │ Heur 45 + ML 35    │  │
                                    │  │ + YARA 20          │  │
                                    │  └─────────┬──────────┘  │
                                    │            ▼             │
                                    │  ┌─────┐  ┌──────────┐   │
                                    │  │ DB  │  │ RQ Queue │   │
                                    │  │ PG  │  │  Redis   │   │
                                    │  └──┬──┘  └────┬─────┘   │
                                    └─────┼──────────┼─────────┘
                                          ▼          ▼
                                       ┌──────┐  ┌────────┐
                                       │ Web  │  │ Worker │
                                       │ SOC  │  │  Scan  │
                                       └──────┘  └────────┘`}
        </pre>
      </section>

      {/* Stack table */}
      <section className="mb-16">
        <h2 className="text-2xl font-bold mb-6">Stack technique</h2>
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900">
              <tr className="text-left">
                <th className="px-4 py-3">Couche</th>
                <th className="px-4 py-3">Technologie</th>
                <th className="px-4 py-3">Rôle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {[
                ['Frontend', 'Vite + React 18 + TypeScript + Tailwind', 'Console SOC + site marketing'],
                ['API', 'FastAPI 0.115 + Pydantic v2', 'Routes REST + OpenAPI'],
                ['ML', 'scikit-learn 1.5 (RandomForest)', 'Score ML [0,1]'],
                ['Rules', 'yara-python 4.5', 'Pattern matching binaire'],
                ['DB', 'PostgreSQL 16 + SQLAlchemy 2', 'Persistance menaces / agents'],
                ['Queue', 'Redis 7 + RQ 2.1', 'Scans asynchrones'],
                ['Agent', 'Python 3.11 + watchdog 6 + httpx', 'Endpoint Windows/Linux'],
                ['Logs', 'structlog 24 JSON', 'Audit trail SOC'],
                ['Auth', 'PyJWT + bcrypt', 'JWT 2 scopes (user 60min / agent 30j)'],
                ['Reverse-proxy', 'nginx 1.27 + TLS', 'Edge production'],
                ['Orchestration', 'Docker Compose v2', 'Dev + Prod'],
              ].map((row) => (
                <tr key={row[0]} className="bg-slate-950 hover:bg-slate-900">
                  <td className="px-4 py-3 font-medium text-brand-300">{row[0]}</td>
                  <td className="px-4 py-3 text-slate-200">{row[1]}</td>
                  <td className="px-4 py-3 text-slate-400">{row[2]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2"><Shield className="text-brand-400" /> Sécurité</h2>
        <div className="grid md:grid-cols-2 gap-4">
          {[
            ['JWT 2 scopes', 'Tokens user (60 min) et agent (30 jours), cryptés HS256, secret généré via openssl rand.'],
            ['CORS strict', 'Whitelist explicite des origines de production.'],
            ['Validation Pydantic', 'Tous les inputs sont schémas-validés avant l\'exécution.'],
            ['Quarantaine isolée', 'Permissions UNIX 700 sur /var/lib/guardian/quarantine.'],
            ['No-root containers', 'Backend tourne en uid 1000 (utilisateur `guardian`).'],
            ['Healthchecks', 'Probes HTTP toutes les 30s, redémarrage automatique sur échec.'],
          ].map((row) => (
            <div key={row[0]} className="rounded-xl bg-slate-900 border border-slate-800 p-5">
              <div className="font-semibold text-brand-300 mb-1">{row[0]}</div>
              <div className="text-sm text-slate-400">{row[1]}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
