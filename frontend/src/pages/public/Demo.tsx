import { Play, FileVideo } from 'lucide-react'
import { Link } from 'react-router-dom'

const VIDEOS = [
  {
    title: 'Détection en temps réel d\'un ransomware',
    desc: 'Un échantillon WannaCry simulé est posé sur le bureau Windows. L\'agent envoie le fichier, GuardIAn renvoie un verdict critical en moins d\'une seconde, le fichier est mis en quarantaine.',
    src: '/media/demo-1.mp4',
    poster: '/img/demo-poster.svg',
    duration: '1m 47s',
  },
  {
    title: 'Console SOC : tableau de bord',
    desc: 'Visite guidée de la console : vue d\'ensemble, agents en ligne, statistiques, gestion des menaces, plans d\'éradication.',
    src: '/media/demo-2.mp4',
    poster: '/img/demo-poster.svg',
    duration: '2m 14s',
  },
  {
    title: 'Analyse manuelle d\'un fichier',
    desc: 'Upload d\'un binaire suspect via la console, extraction des 14 features, score décomposé Heuristique / ML / YARA, recommandations CERT-TG.',
    src: '/media/demo-3.mp4',
    poster: '/img/demo-poster.svg',
    duration: '0m 58s',
  },
  {
    title: 'Scan complet d\'un répertoire',
    desc: 'Lancement d\'un scan sur /home/user, polling temps réel, suivi de l\'avancement, rapport final avec menaces classées par sévérité.',
    src: '/media/demo-4.mp4',
    poster: '/img/demo-poster.svg',
    duration: '1m 32s',
  },
]

export default function Demo() {
  return (
    <div className="max-w-6xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">Démos vidéo</h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          Chaque clip dure moins de 3 minutes et illustre un scénario d'usage réel.
        </p>
      </div>

      <div className="grid md:grid-cols-2 gap-8">
        {VIDEOS.map((v) => (
          <div key={v.title} className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden">
            <div className="aspect-video bg-slate-950 relative group">
              <video controls poster={v.poster} preload="metadata" className="w-full h-full">
                <source src={v.src} type="video/mp4" />
                Votre navigateur ne supporte pas la lecture vidéo.
              </video>
              <div className="absolute top-3 right-3 bg-black/70 text-white text-xs px-2 py-1 rounded flex items-center gap-1 pointer-events-none">
                <FileVideo className="w-3 h-3" /> {v.duration}
              </div>
            </div>
            <div className="p-5">
              <h3 className="font-semibold text-lg mb-2">{v.title}</h3>
              <p className="text-sm text-slate-400">{v.desc}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-16 text-center">
        <h2 className="text-2xl font-bold mb-4">Vous voulez essayer vous-même ?</h2>
        <p className="text-slate-400 mb-6">La console SOC est accessible immédiatement après installation.</p>
        <div className="flex flex-wrap justify-center gap-4">
          <Link to="/login" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-brand-500 hover:bg-brand-400 text-white font-medium">
            <Play className="w-4 h-4" /> Accéder à la console
          </Link>
          <Link to="/architecture" className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-slate-700 hover:bg-slate-800">
            Comment ça marche
          </Link>
        </div>
      </div>
    </div>
  )
}
