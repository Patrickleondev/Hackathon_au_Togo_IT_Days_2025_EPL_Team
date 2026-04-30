import { Mail, Github, Phone, MapPin, Send } from 'lucide-react'
import { useState } from 'react'

export default function Contact() {
  const [sent, setSent] = useState(false)
  return (
    <div className="max-w-5xl mx-auto px-4 py-20">
      <div className="text-center mb-16">
        <h1 className="text-4xl md:text-5xl font-bold mb-4">Contact</h1>
        <p className="text-slate-400 max-w-xl mx-auto">
          Une question, une démo, une vulnérabilité à signaler ? Voici comment nous joindre.
        </p>
      </div>

      <div className="grid md:grid-cols-2 gap-8">
        {/* Contact info */}
        <div className="space-y-4">
          {[
            { icon: Mail, label: 'Email équipe', value: 'epl-team@togoitdays.tg', href: 'mailto:epl-team@togoitdays.tg' },
            { icon: Github, label: 'Code source', value: 'github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team', href: 'https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team' },
            { icon: Phone, label: 'CERT-TG (urgences cyber)', value: '(+228) 70 54 93 25', href: 'tel:+22870549325' },
            { icon: MapPin, label: 'Adresse', value: 'École Polytechnique de Lomé, Togo' },
          ].map((c) => {
            const Icon = c.icon
            const Inner = (
              <>
                <div className="p-3 rounded-lg bg-brand-900/40 border border-brand-800">
                  <Icon className="w-5 h-5 text-brand-400" />
                </div>
                <div>
                  <div className="text-xs text-slate-400 mb-1">{c.label}</div>
                  <div className="font-medium break-all">{c.value}</div>
                </div>
              </>
            )
            return c.href ? (
              <a key={c.label} href={c.href} target={c.href.startsWith('http') ? '_blank' : undefined} rel="noreferrer"
                className="flex items-start gap-4 rounded-xl bg-slate-900 border border-slate-800 p-5 hover:border-brand-700 transition-colors">
                {Inner}
              </a>
            ) : (
              <div key={c.label} className="flex items-start gap-4 rounded-xl bg-slate-900 border border-slate-800 p-5">{Inner}</div>
            )
          })}
        </div>

        {/* Form (mock — POSTs to /api/contact later) */}
        <form
          onSubmit={(e) => { e.preventDefault(); setSent(true) }}
          className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4"
        >
          <h2 className="font-semibold text-lg">Envoyer un message</h2>
          {sent ? (
            <div className="rounded-lg bg-emerald-900/30 border border-emerald-800 p-4 text-emerald-200 text-sm">
              Merci, votre message est noté. L'équipe EPL vous recontactera.
            </div>
          ) : (
            <>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Nom</label>
                <input className="input w-full" required placeholder="Votre nom" />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Email</label>
                <input type="email" className="input w-full" required placeholder="vous@exemple.com" />
              </div>
              <div>
                <label className="text-xs text-slate-400 mb-1 block">Message</label>
                <textarea className="input w-full min-h-[120px]" required placeholder="Comment pouvons-nous aider ?" />
              </div>
              <button type="submit" className="btn-primary inline-flex items-center gap-2">
                <Send className="w-4 h-4" /> Envoyer
              </button>
              <p className="text-xs text-slate-500">
                Pour signaler une vulnérabilité de sécurité, préférez l'email direct (chiffrement PGP disponible).
              </p>
            </>
          )}
        </form>
      </div>
    </div>
  )
}
