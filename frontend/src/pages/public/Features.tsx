import { Brain, Eye, Lock, Network, Shield, Server, Zap, Cpu, FileSearch, AlertTriangle, Database, Activity, Workflow, BarChart3 } from 'lucide-react'

const SECTIONS = [
  {
    title: 'Détection',
    icon: Brain,
    items: [
      { icon: FileSearch, title: 'Extraction de 14 features', text: 'Taille, entropie de Shannon, magic mismatch, extension, pattern hits (vssadmin, bcdedit, ransom note, BTC), imports PE suspects, sections, ratios.' },
      { icon: Brain, title: 'Random Forest pondéré', text: 'Entraîné sur EMBER + jeux locaux, 200 estimators, class_weight balanced. Score normalisé [0,1].' },
      { icon: Shield, title: 'Règles YARA', text: 'Catalogue intégré (generic, locker, double-extortion). Mises à jour à chaud sans redémarrage.' },
      { icon: Workflow, title: 'Agrégation pondérée', text: 'Heuristique 45% + ML 35% + YARA 20%. Si modèle ML absent, heuristique passe à 100%.' },
    ],
  },
  {
    title: 'Surveillance & Endpoint',
    icon: Eye,
    items: [
      { icon: Cpu, title: 'Agent Windows / Linux', text: 'Watchdog filesystem, triage local par heuristiques. < 1% CPU, < 50 MB RAM.' },
      { icon: Activity, title: 'Heartbeat', text: 'Métriques système toutes les 30s : CPU, RAM, uptime, dernière analyse.' },
      { icon: Network, title: 'Communication chiffrée', text: 'TLS 1.3, JWT scope agent (30j), upload multipart sécurisé avec taille max configurable.' },
      { icon: Database, title: 'Hors-ligne tolérant', text: 'L\'agent met en file d\'attente les uploads en cas de coupure réseau.' },
    ],
  },
  {
    title: 'Réponse aux incidents',
    icon: Lock,
    items: [
      { icon: Lock, title: 'Quarantaine immédiate', text: 'Déplacement vers `/var/lib/guardian/quarantine` avec préfixe horodaté.' },
      { icon: AlertTriangle, title: 'Plans d\'éradication', text: 'Scripts atomiques : kill-process, isolate-host, restore-shadow-copies, block-c2.' },
      { icon: Network, title: 'Isolation réseau', text: 'Coupure des connexions sortantes vers C2 connus (intégration firewall optionnelle).' },
      { icon: BarChart3, title: 'Audit trail', text: 'Toutes les actions sont journalisées (structlog JSON) et conservées en base.' },
    ],
  },
  {
    title: 'Plateforme SOC',
    icon: Server,
    items: [
      { icon: Server, title: 'Console web', text: 'Tableau de bord temps réel : menaces, agents, statistiques système, polling 5s.' },
      { icon: Cpu, title: 'API REST OpenAPI', text: 'Documentation Swagger automatique sur /docs, contract-first.' },
      { icon: Zap, title: 'Workers asynchrones', text: 'RQ + Redis pour les scans longs. Scalable horizontalement.' },
      { icon: Database, title: 'Postgres 16', text: 'Stockage durable des menaces, agents, scans, éradications.' },
    ],
  },
]

export default function Features() {
  return (
    <div className="max-w-6xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">Fonctionnalités</h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          Tout ce que vous attendez d'une solution SOC moderne, dans un paquet open-source unique.
        </p>
      </div>
      <div className="space-y-20">
        {SECTIONS.map((s) => {
          const SIcon = s.icon
          return (
            <section key={s.title}>
              <div className="flex items-center gap-3 mb-8">
                <div className="p-3 rounded-lg bg-brand-900/40 border border-brand-800">
                  <SIcon className="w-6 h-6 text-brand-400" />
                </div>
                <h2 className="text-2xl md:text-3xl font-bold">{s.title}</h2>
              </div>
              <div className="grid md:grid-cols-2 gap-4">
                {s.items.map((it) => {
                  const Icon = it.icon
                  return (
                    <div key={it.title} className="rounded-xl bg-slate-900 border border-slate-800 p-5 flex gap-4">
                      <Icon className="w-8 h-8 text-brand-400 flex-shrink-0" />
                      <div>
                        <h3 className="font-semibold mb-1">{it.title}</h3>
                        <p className="text-sm text-slate-400">{it.text}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </section>
          )
        })}
      </div>
    </div>
  )
}
