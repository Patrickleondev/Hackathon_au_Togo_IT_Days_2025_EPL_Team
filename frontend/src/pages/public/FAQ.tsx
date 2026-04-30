import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Search, ChevronDown, MessageCircle, AlertCircle } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import clsx from 'clsx'
import { Assistant, type FAQItem } from '../../api/client'

type CategoryKey = 'all' | 'general' | 'detection' | 'deployment' | 'ml' | 'team'

const CATEGORY_ORDER: CategoryKey[] = ['all', 'general', 'detection', 'deployment', 'ml', 'team']

function normalise(text: string): string {
  return text
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
}

export default function FAQ() {
  const { t, i18n } = useTranslation()
  const lang = (i18n.resolvedLanguage || 'fr').slice(0, 2) as 'fr' | 'en'

  const [items, setItems] = useState<FAQItem[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<CategoryKey>('all')
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  // Fetch the catalog for the active language. Re-fetch on language change.
  useEffect(() => {
    let cancelled = false
    setItems(null)
    setError(null)
    Assistant.faq(lang)
      .then((rows) => {
        if (cancelled) return
        setItems(rows)
        // If the URL contains a hash like #install-agent, expand & scroll to it.
        const hash = window.location.hash.replace(/^#/, '')
        if (hash) {
          setExpanded((s) => {
            const next = new Set(s)
            next.add(hash)
            return next
          })
          window.setTimeout(() => {
            const el = document.getElementById(hash)
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
          }, 50)
        }
      })
      .catch(() => {
        if (!cancelled) setError(t('faq.error'))
      })
    return () => {
      cancelled = true
    }
  }, [lang, t])

  const visible = useMemo(() => {
    if (!items) return []
    const q = normalise(query.trim())
    return items.filter((it) => {
      if (category !== 'all' && it.category !== category) return false
      if (!q) return true
      const hay = normalise(it.question + ' ' + it.answer)
      return hay.includes(q)
    })
  }, [items, query, category])

  function toggle(id: string) {
    setExpanded((s) => {
      const next = new Set(s)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-4xl font-bold text-white mb-3">{t('faq.title')}</h1>
        <p className="text-slate-400 max-w-2xl mx-auto">{t('faq.subtitle')}</p>
      </div>

      {/* Search bar */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('faq.searchPlaceholder')}
          className="w-full pl-9 pr-3 py-2.5 rounded-md bg-slate-900 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:border-brand-400"
        />
      </div>

      {/* Category filters */}
      <div className="flex flex-wrap gap-2 mb-8">
        {CATEGORY_ORDER.map((c) => (
          <button
            key={c}
            type="button"
            onClick={() => setCategory(c)}
            className={clsx(
              'px-3 py-1 text-xs rounded-full border transition-colors',
              category === c
                ? 'bg-brand-500 border-brand-400 text-white'
                : 'bg-slate-900 border-slate-700 text-slate-300 hover:border-brand-500 hover:text-white',
            )}
          >
            {t(`faq.categories.${c}`)}
          </button>
        ))}
      </div>

      {/* States */}
      {!items && !error && (
        <div className="text-center py-12 text-slate-400 text-sm">{t('faq.loading')}</div>
      )}
      {error && (
        <div className="flex items-center gap-2 text-amber-300 bg-amber-900/30 border border-amber-700/50 rounded px-3 py-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Results */}
      {items && visible.length === 0 && (
        <div className="text-center py-12 text-slate-400 text-sm">{t('faq.noResults')}</div>
      )}

      <ul className="space-y-2">
        {visible.map((it) => {
          const open = expanded.has(it.id)
          return (
            <li
              key={it.id}
              id={it.id}
              className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden"
            >
              <button
                type="button"
                onClick={() => toggle(it.id)}
                aria-expanded={open}
                className="w-full flex items-center justify-between gap-4 px-4 py-3 text-left hover:bg-slate-800/50 transition-colors"
              >
                <span className="font-medium text-white">{it.question}</span>
                <ChevronDown
                  className={clsx('w-4 h-4 text-slate-400 transition-transform shrink-0', open && 'rotate-180')}
                />
              </button>
              {open && (
                <div className="px-4 pb-4 pt-1 border-t border-slate-800 bg-slate-950/30">
                  <div className="text-sm text-slate-200 leading-relaxed [&_p]:my-2 [&_strong]:text-white [&_a]:text-brand-300 [&_a]:underline [&_code]:text-brand-300 [&_code]:bg-slate-900 [&_code]:px-1 [&_code]:rounded [&_ul]:list-disc [&_ul]:ml-5 [&_ol]:list-decimal [&_ol]:ml-5">
                    <ReactMarkdown>{it.answer}</ReactMarkdown>
                  </div>
                  <div className="mt-3 text-[11px] uppercase tracking-wide text-slate-500">
                    {t(`faq.categories.${it.category}` as `faq.categories.${CategoryKey}`, { defaultValue: it.category })}
                  </div>
                </div>
              )}
            </li>
          )
        })}
      </ul>

      {/* CTA to chatbot */}
      <div className="mt-10 rounded-xl border border-slate-800 bg-gradient-to-br from-slate-900 to-slate-950 p-6 text-center">
        <MessageCircle className="w-6 h-6 text-brand-400 mx-auto mb-2" />
        <p className="text-slate-300">{t('faq.askAssistant')}</p>
      </div>
    </div>
  )
}
