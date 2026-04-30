import { useTranslation } from 'react-i18next'
import { Languages } from 'lucide-react'
import clsx from 'clsx'

const LANGS = [
  { code: 'fr', label: 'FR' },
  { code: 'en', label: 'EN' },
] as const

export default function LanguageSwitcher({ className }: { className?: string }) {
  const { i18n, t } = useTranslation()
  const current = (i18n.resolvedLanguage || i18n.language || 'fr').slice(0, 2)

  return (
    <div
      className={clsx(
        'inline-flex items-center gap-0.5 rounded-md bg-slate-800/60 border border-slate-700 p-0.5',
        className,
      )}
      role="group"
      aria-label={t('lang.switch')}
    >
      <Languages className="w-4 h-4 ml-1.5 mr-0.5 text-slate-400" aria-hidden />
      {LANGS.map((l) => {
        const active = current === l.code
        return (
          <button
            key={l.code}
            type="button"
            onClick={() => void i18n.changeLanguage(l.code)}
            className={clsx(
              'px-2 py-0.5 text-xs font-medium rounded transition-colors',
              active
                ? 'bg-brand-500 text-white shadow'
                : 'text-slate-300 hover:text-white hover:bg-slate-700',
            )}
            aria-pressed={active}
            aria-label={t(`lang.${l.code}` as 'lang.fr' | 'lang.en')}
          >
            {l.label}
          </button>
        )
      })}
    </div>
  )
}
