import { GraduationCap, Target, Users, Award, MapPin } from 'lucide-react'

export default function About() {
  return (
    <div className="max-w-5xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">À propos de GuardIAn</h1>
        <p className="text-slate-400 max-w-2xl mx-auto">
          Un projet ambitieux né au Togo pour répondre à un besoin africain de souveraineté numérique.
        </p>
      </div>

      <section className="rounded-xl bg-slate-900 border border-slate-800 p-8 mb-12">
        <Target className="w-8 h-8 text-brand-400 mb-4" />
        <h2 className="text-2xl font-bold mb-4">Notre mission</h2>
        <p className="text-slate-300 leading-relaxed">
          Les ransomwares ont coûté plus de 30 milliards de dollars en 2024 dans le monde, dont une part croissante en Afrique de l'Ouest où la cybersécurité reste sous-financée. La plupart des solutions de protection sont propriétaires, payantes en devises étrangères, et envoient les données vers des cloud étrangers — ce qui pose des problèmes de souveraineté et de coût.
        </p>
        <p className="text-slate-300 leading-relaxed mt-4">
          <strong className="text-brand-300">GuardIAn</strong> est notre réponse : une plateforme de détection et de réponse aux ransomwares <strong>open-source</strong>, <strong>auto-hébergeable</strong>, <strong>francophone</strong>, et conçue pour être déployable même sur du matériel modeste.
        </p>
      </section>

      <section className="rounded-xl bg-slate-900 border border-slate-800 p-8 mb-12">
        <GraduationCap className="w-8 h-8 text-brand-400 mb-4" />
        <h2 className="text-2xl font-bold mb-4">L'équipe EPL</h2>
        <p className="text-slate-300 leading-relaxed">
          Nous sommes étudiants à l'<strong>École Polytechnique de Lomé</strong>, passionnés par l'IA et la cybersécurité. Ce projet a été conçu, développé et soutenu pour le <strong>Hackathon des Togo IT Days 2025</strong>.
        </p>
        <div className="grid md:grid-cols-3 gap-4 mt-6">
          {[
            { icon: Users, label: 'Équipe', value: '4 développeurs' },
            { icon: MapPin, label: 'Localisation', value: 'Lomé, Togo' },
            { icon: Award, label: 'Évènement', value: 'Togo IT Days 2025' },
          ].map((s) => {
            const Icon = s.icon
            return (
              <div key={s.label} className="rounded-lg bg-slate-950 border border-slate-800 p-5 text-center">
                <Icon className="w-6 h-6 text-brand-400 mx-auto mb-2" />
                <div className="text-xs text-slate-400">{s.label}</div>
                <div className="font-semibold mt-1">{s.value}</div>
              </div>
            )
          })}
        </div>
      </section>

      <section className="rounded-xl bg-gradient-to-br from-brand-900/40 to-slate-900 border border-brand-800 p-8">
        <h2 className="text-2xl font-bold mb-4">Nos valeurs</h2>
        <div className="grid md:grid-cols-2 gap-6">
          {[
            ['Open-source', 'Le code source est disponible publiquement sous licence Apache-2.0. Auditez, forkez, contribuez.'],
            ['Souveraineté', 'Vos données restent chez vous. Aucun appel sortant non documenté, aucune télémétrie cachée.'],
            ['Frugal', 'Tourne sur 2 vCPU / 4 GB RAM. Pensé pour les infrastructures africaines.'],
            ['Francophone', 'Documentation, interface et support en français.'],
          ].map((row) => (
            <div key={row[0]}>
              <div className="font-semibold text-brand-300 mb-1">{row[0]}</div>
              <div className="text-sm text-slate-400">{row[1]}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
