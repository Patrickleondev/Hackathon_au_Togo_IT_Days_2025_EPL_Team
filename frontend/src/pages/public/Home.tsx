import { Link } from 'react-router-dom'
import {
  Shield, Brain, Network, Zap, Lock, Eye, Cpu, Server, ArrowRight, Play, FileSearch, AlertTriangle,
} from 'lucide-react'
import { motion } from 'framer-motion'

const FEATURES = [
  { icon: Brain, title: 'Détection IA hybride', text: 'Heuristique 14-features + Random Forest + YARA, agrégation pondérée pour minimiser les faux positifs.' },
  { icon: Eye, title: 'Surveillance temps réel', text: 'Agent Windows/Linux watchdog → upload uniquement si suspect, < 1% CPU.' },
  { icon: Network, title: 'Architecture SOC', text: 'Console centrale FastAPI + workers RQ + Postgres + Redis. Multi-endpoints natif.' },
  { icon: Lock, title: 'Quarantaine & remédiation', text: 'Plans d\'éradication scriptés, isolation réseau, restauration des shadow copies.' },
  { icon: Zap, title: 'Latence sub-seconde', text: 'Verdict en < 800 ms par fichier sur CPU modeste (4 vCPU).' },
  { icon: Server, title: 'Auto-hébergeable', text: 'Docker Compose en 2 commandes. Aucun cloud requis. Données 100% sous votre contrôle.' },
]

const STATS = [
  { value: '14', label: 'Features extraites par fichier' },
  { value: '< 800ms', label: 'Latence verdict' },
  { value: '95%+', label: 'Précision sur jeu de test' },
  { value: '< 1%', label: 'CPU agent endpoint' },
]

const STEPS = [
  { n: '01', title: 'Agent endpoint', text: 'Le watcher détecte un nouveau fichier suspect (extension, magic, entropie).' },
  { n: '02', title: 'Upload sécurisé', text: 'JWT-auth multipart vers /api/analyze/agent-file, taille max configurable.' },
  { n: '03', title: 'Détecteur unifié', text: '14 features → Heuristique (45%) + ML (35%) + YARA (20%).' },
  { n: '04', title: 'Verdict & action', text: 'Score → sévérité → quarantaine, alerte SOC, eradication automatique optionnelle.' },
]

export default function Home() {
  return (
    <>
      {/* HERO */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-brand-900/30 via-slate-950 to-slate-950" />
        <div className="absolute inset-0 opacity-30 [background-image:radial-gradient(circle_at_30%_20%,rgba(59,130,246,0.3),transparent_40%),radial-gradient(circle_at_70%_60%,rgba(16,185,129,0.2),transparent_40%)]" />
        <div className="relative max-w-6xl mx-auto px-4 py-24 md:py-32">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl"
          >
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-900/50 border border-brand-700 text-brand-300 text-xs mb-6">
              <Shield className="w-3 h-3" /> Hackathon Togo IT Days 2025 — Équipe EPL
            </div>
            <h1 className="text-4xl md:text-6xl font-bold leading-tight mb-6">
              Stoppez les <span className="text-brand-400">ransomwares</span> avant qu'ils ne chiffrent.
            </h1>
            <p className="text-lg md:text-xl text-slate-300 mb-8">
              <strong>GuardIAn</strong> est une plateforme SOC souveraine, open-source, qui combine intelligence artificielle,
              règles YARA et heuristiques avancées pour détecter, isoler et neutraliser les rançongiciels en temps réel
              sur tous vos endpoints.
            </p>
            <div className="flex flex-wrap gap-4">
              <Link to="/demo" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-brand-500 hover:bg-brand-400 text-white font-medium">
                <Play className="w-4 h-4" /> Voir la démo
              </Link>
              <Link to="/architecture" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-100">
                Architecture <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </motion.div>

          {/* Floating dashboard preview */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.7, delay: 0.3 }}
            className="mt-16 rounded-xl border border-slate-800 bg-slate-900/70 backdrop-blur p-2 shadow-2xl shadow-brand-900/40"
          >
            <div className="rounded-lg bg-slate-950 px-4 py-3 flex items-center gap-2 border-b border-slate-800">
              <span className="w-3 h-3 rounded-full bg-red-500" />
              <span className="w-3 h-3 rounded-full bg-yellow-500" />
              <span className="w-3 h-3 rounded-full bg-green-500" />
              <span className="ml-3 text-xs text-slate-500">guardian.local — Console SOC</span>
            </div>
            <div className="grid md:grid-cols-3 gap-4 p-6">
              {[
                { label: 'Menaces 24h', value: '12', color: 'text-red-400', icon: AlertTriangle },
                { label: 'Endpoints', value: '47', color: 'text-emerald-400', icon: Cpu },
                { label: 'Fichiers analysés', value: '8 391', color: 'text-brand-400', icon: FileSearch },
              ].map((s) => {
                const Icon = s.icon
                return (
                  <div key={s.label} className="rounded-lg bg-slate-900 border border-slate-800 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-slate-400">{s.label}</span>
                      <Icon className={`w-4 h-4 ${s.color}`} />
                    </div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                  </div>
                )
              })}
            </div>
          </motion.div>
        </div>
      </section>

      {/* FEATURES GRID */}
      <section className="py-20 px-4 bg-slate-950">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Une protection multi-couches</h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Chaque fichier est analysé par trois systèmes complémentaires pour réduire les faux positifs et capter les menaces zero-day.
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            {FEATURES.map((f, i) => (
              <motion.div
                key={f.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className="rounded-xl bg-slate-900 border border-slate-800 p-6 hover:border-brand-700 transition-colors"
              >
                <f.icon className="w-8 h-8 text-brand-400 mb-3" />
                <h3 className="font-semibold text-lg mb-2">{f.title}</h3>
                <p className="text-sm text-slate-400">{f.text}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* STATS */}
      <section className="py-16 px-4 bg-gradient-to-b from-brand-900/20 to-transparent border-y border-slate-800">
        <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
          {STATS.map((s) => (
            <div key={s.label} className="text-center">
              <div className="text-3xl md:text-4xl font-bold text-brand-400">{s.value}</div>
              <div className="text-xs md:text-sm text-slate-400 mt-2">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="py-20 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Le flux de détection</h2>
            <p className="text-slate-400">De l'écriture du fichier à l'éradication, en moins d'une seconde.</p>
          </div>
          <div className="grid md:grid-cols-4 gap-6">
            {STEPS.map((s) => (
              <div key={s.n} className="rounded-xl bg-slate-900 border border-slate-800 p-6 relative overflow-hidden">
                <div className="text-5xl font-bold text-brand-900 absolute top-2 right-3">{s.n}</div>
                <h3 className="font-semibold text-lg mb-2 relative">{s.title}</h3>
                <p className="text-sm text-slate-400 relative">{s.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* MINI VIDEO TEASER */}
      <section className="py-20 px-4 bg-slate-900/50 border-y border-slate-800">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-3xl md:text-4xl font-bold mb-3">Voyez GuardIAn en action</h2>
            <p className="text-slate-400">Une démo de 2 minutes : du fichier suspect au verdict en direct.</p>
          </div>
          <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950 aspect-video flex items-center justify-center relative group">
            {/* video placeholder — replace src with real demo */}
            <video
              className="w-full h-full"
              controls
              poster="/img/demo-poster.svg"
              preload="metadata"
            >
              <source src="/media/demo.mp4" type="video/mp4" />
              Votre navigateur ne supporte pas la lecture vidéo.
            </video>
          </div>
          <div className="mt-6 text-center">
            <Link to="/demo" className="inline-flex items-center gap-2 text-brand-400 hover:text-brand-300">
              Voir toutes les démos <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-4">
        <div className="max-w-4xl mx-auto rounded-2xl bg-gradient-to-r from-brand-700 to-brand-500 p-10 md:p-14 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Déployable en 5 minutes</h2>
          <p className="text-brand-100 mb-8 text-lg">
            Une commande Docker Compose, une console web, et vos endpoints sont protégés. Aucun cloud, aucun éditeur tiers.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <a
              href="https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team"
              target="_blank"
              rel="noreferrer"
              className="px-6 py-3 rounded-lg bg-white text-brand-700 font-medium hover:bg-brand-50"
            >
              Voir sur GitHub
            </a>
            <Link to="/contact" className="px-6 py-3 rounded-lg border border-white/40 hover:bg-white/10 text-white font-medium">
              Nous contacter
            </Link>
          </div>
        </div>
      </section>
    </>
  )
}
