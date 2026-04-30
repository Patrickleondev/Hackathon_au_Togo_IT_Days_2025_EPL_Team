import { Link, NavLink, Outlet } from 'react-router-dom'
import { Shield, Menu, X } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import clsx from 'clsx'
import LanguageSwitcher from './LanguageSwitcher'
import ChatBot from './ChatBot'

export default function PublicLayout() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  const NAV: { to: string; key: 'home' | 'features' | 'architecture' | 'demo' | 'faq' | 'about' | 'contact' }[] = [
    { to: '/', key: 'home' },
    { to: '/features', key: 'features' },
    { to: '/architecture', key: 'architecture' },
    { to: '/demo', key: 'demo' },
    { to: '/faq', key: 'faq' },
    { to: '/about', key: 'about' },
    { to: '/contact', key: 'contact' },
  ]

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      <header className="sticky top-0 z-40 bg-slate-950/80 backdrop-blur border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-bold text-lg">
            <Shield className="text-brand-400" />
            <span>GuardIAn</span>
            <span className="text-xs px-2 py-0.5 rounded bg-brand-900/60 text-brand-300 ml-1">v2.0</span>
          </Link>
          <nav className="hidden md:flex items-center gap-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.to === '/'}
                className={({ isActive }) =>
                  clsx(
                    'px-3 py-1.5 rounded text-sm transition-colors',
                    isActive ? 'text-brand-300 bg-brand-900/40' : 'text-slate-300 hover:text-white hover:bg-slate-800',
                  )
                }
              >
                {t(`nav.${n.key}`)}
              </NavLink>
            ))}
            <LanguageSwitcher className="ml-2" />
            <Link
              to="/login"
              className="ml-2 px-4 py-1.5 rounded bg-brand-500 hover:bg-brand-400 text-white text-sm font-medium"
            >
              {t('nav.console')}
            </Link>
          </nav>
          <button
            className="md:hidden text-slate-200"
            onClick={() => setOpen(!open)}
            aria-label={t('nav.menu')}
          >
            {open ? <X /> : <Menu />}
          </button>
        </div>
        {open && (
          <div className="md:hidden border-t border-slate-800 px-4 py-3 flex flex-col gap-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.to === '/'}
                onClick={() => setOpen(false)}
                className="px-2 py-2 rounded text-slate-300 hover:bg-slate-800"
              >
                {t(`nav.${n.key}`)}
              </NavLink>
            ))}
            <div className="px-2 py-2">
              <LanguageSwitcher />
            </div>
            <Link to="/login" onClick={() => setOpen(false)} className="mt-2 px-4 py-2 rounded bg-brand-500 text-center">
              {t('nav.console')}
            </Link>
          </div>
        )}
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      <footer className="border-t border-slate-800 py-10 px-4">
        <div className="max-w-6xl mx-auto grid md:grid-cols-3 gap-8 text-sm">
          <div>
            <div className="flex items-center gap-2 font-bold text-base mb-3">
              <Shield className="text-brand-400" /> GuardIAn
            </div>
            <p className="text-slate-400">{t('footer.tagline')}</p>
          </div>
          <div>
            <div className="font-semibold mb-2 text-slate-200">{t('footer.product')}</div>
            <ul className="space-y-1 text-slate-400">
              <li><Link to="/features" className="hover:text-white">{t('nav.features')}</Link></li>
              <li><Link to="/architecture" className="hover:text-white">{t('nav.architecture')}</Link></li>
              <li><Link to="/demo" className="hover:text-white">{t('nav.demo')}</Link></li>
              <li><Link to="/faq" className="hover:text-white">{t('nav.faq')}</Link></li>
              <li>
                <a
                  href="https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-white"
                >
                  {t('footer.sourceCode')}
                </a>
              </li>
            </ul>
          </div>
          <div>
            <div className="font-semibold mb-2 text-slate-200">{t('footer.team')}</div>
            <ul className="space-y-1 text-slate-400">
              <li>{t('footer.school')}</li>
              <li>{t('footer.hackathon')}</li>
              <li>{t('footer.cert')}</li>
              <li><Link to="/contact" className="hover:text-white">{t('footer.contactUs')}</Link></li>
            </ul>
          </div>
        </div>
        <div className="max-w-6xl mx-auto mt-8 pt-6 border-t border-slate-800 text-xs text-slate-500 flex flex-col md:flex-row md:justify-between gap-2">
          <span>{t('footer.copyright')}</span>
          <span>{t('footer.build', { date: new Date().toISOString().slice(0, 10) })}</span>
        </div>
      </footer>

      {/* Floating chat assistant — visible on every public page. */}
      <ChatBot />
    </div>
  )
}
