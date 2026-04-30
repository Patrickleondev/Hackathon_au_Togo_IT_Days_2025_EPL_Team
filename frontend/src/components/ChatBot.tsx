import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { AnimatePresence, motion } from 'framer-motion'
import { Bot, MessageCircle, Send, Sparkles, X, RotateCcw, AlertTriangle } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import clsx from 'clsx'
import { Assistant, type ChatReply, type RelatedFAQ } from '../api/client'

type Role = 'user' | 'assistant'

interface Message {
  id: string
  role: Role
  text: string
  source?: ChatReply['source']
  provider?: string | null
  related?: RelatedFAQ[]
  ts: number
}

interface ProviderState {
  configured: boolean
  provider: string
  model?: string | null
}

const STORAGE_KEY = 'guardian.chat.history.v1'
const MAX_HISTORY = 30

function newId(): string {
  return Math.random().toString(36).slice(2, 10)
}

function loadHistory(): Message[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as Message[]
    return Array.isArray(parsed) ? parsed.slice(-MAX_HISTORY) : []
  } catch {
    return []
  }
}

function saveHistory(messages: Message[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-MAX_HISTORY)))
  } catch {
    /* quota exceeded — ignore, chat still works in-memory */
  }
}

export default function ChatBot() {
  const { t, i18n } = useTranslation()
  const lang = (i18n.resolvedLanguage || 'fr').slice(0, 2) as 'fr' | 'en'

  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<Message[]>(() => loadHistory())
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [providerInfo, setProviderInfo] = useState<ProviderState | null>(null)

  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Persist chat history.
  useEffect(() => {
    saveHistory(messages)
  }, [messages])

  // Refresh suggestions whenever the panel opens or the language changes.
  useEffect(() => {
    if (!open) return
    let cancelled = false
    Assistant.suggestions(lang)
      .then((s) => {
        if (!cancelled) setSuggestions(s)
      })
      .catch(() => {
        if (!cancelled) setSuggestions([])
      })
    return () => {
      cancelled = true
    }
  }, [open, lang])

  // Probe provider once — used to label the answer source.
  useEffect(() => {
    Assistant.provider()
      .then(setProviderInfo)
      .catch(() => setProviderInfo({ configured: false, provider: 'none' }))
  }, [])

  // Auto-scroll to the bottom on new messages.
  useEffect(() => {
    if (!open) return
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, pending, open])

  // Focus the textarea when the widget opens.
  useEffect(() => {
    if (open) {
      const id = window.setTimeout(() => inputRef.current?.focus(), 250)
      return () => window.clearTimeout(id)
    }
  }, [open])

  const welcomeShown = messages.length > 0

  async function send(text: string) {
    const trimmed = text.trim()
    if (!trimmed || pending) return

    const userMsg: Message = { id: newId(), role: 'user', text: trimmed, ts: Date.now() }
    setMessages((m) => [...m, userMsg])
    setInput('')
    setPending(true)
    setError(null)

    try {
      const reply = await Assistant.send(trimmed, lang)
      const botMsg: Message = {
        id: newId(),
        role: 'assistant',
        text: reply.text,
        source: reply.source,
        provider: reply.provider,
        related: reply.related,
        ts: Date.now(),
      }
      setMessages((m) => [...m, botMsg])
    } catch (err) {
      // axios wraps the response on err.response
      const status = (err as { response?: { status?: number } })?.response?.status
      setError(status === 429 ? t('chatbot.errorRate') : t('chatbot.errorGeneric'))
    } finally {
      setPending(false)
    }
  }

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    void send(input)
  }

  function clearChat() {
    setMessages([])
    setError(null)
    saveHistory([])
  }

  const sourceLabel = useMemo(() => {
    return (m: Message) => {
      if (m.role !== 'assistant' || !m.source) return null
      if (m.source === 'llm')
        return t('chatbot.poweredLLM', { provider: m.provider ?? 'AI' })
      if (m.source === 'fallback') return t('chatbot.poweredFallback')
      return t('chatbot.poweredKB')
    }
  }, [t])

  return (
    <>
      {/* Launcher button */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? t('chatbot.close') : t('chatbot.open')}
        className={clsx(
          'fixed bottom-5 right-5 z-50 h-14 w-14 rounded-full shadow-lg flex items-center justify-center text-white transition-transform',
          'bg-gradient-to-br from-brand-500 to-brand-700 hover:scale-105 focus:outline-none focus:ring-2 focus:ring-brand-400',
        )}
      >
        {open ? <X className="w-6 h-6" /> : <MessageCircle className="w-6 h-6" />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 30, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 30, scale: 0.95 }}
            transition={{ duration: 0.18 }}
            className="fixed bottom-24 right-5 z-50 w-[min(420px,calc(100vw-2.5rem))] h-[min(620px,calc(100vh-8rem))] flex flex-col rounded-xl border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden"
            role="dialog"
            aria-label={t('chatbot.title')}
          >
            {/* Header */}
            <div className="flex items-center gap-2 px-4 h-14 border-b border-slate-800 bg-gradient-to-r from-slate-900 to-slate-800">
              <div className="h-8 w-8 rounded-full bg-brand-500/20 flex items-center justify-center">
                <Bot className="w-5 h-5 text-brand-300" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-white truncate">{t('chatbot.title')}</div>
                {providerInfo && (
                  <div className="text-[11px] text-slate-400 truncate flex items-center gap-1">
                    <Sparkles className="w-3 h-3" />
                    {providerInfo.configured
                      ? `${providerInfo.provider}${providerInfo.model ? ' · ' + providerInfo.model : ''}`
                      : 'Knowledge base only'}
                  </div>
                )}
              </div>
              {messages.length > 0 && (
                <button
                  type="button"
                  onClick={clearChat}
                  aria-label={t('chatbot.newChat')}
                  className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800"
                  title={t('chatbot.newChat')}
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              )}
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label={t('chatbot.close')}
                className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Messages */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-4 space-y-3">
              {!welcomeShown && (
                <div className="rounded-lg bg-slate-800/60 border border-slate-700 px-3 py-2 text-sm text-slate-200">
                  {t('chatbot.welcome')}
                </div>
              )}

              {messages.map((m) => (
                <Bubble key={m.id} msg={m} sourceLabel={sourceLabel(m)} relatedLabel={t('chatbot.related')} />
              ))}

              {pending && (
                <div className="flex items-center gap-2 text-xs text-slate-400 px-1">
                  <span className="inline-flex gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-bounce" />
                    <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-bounce [animation-delay:120ms]" />
                    <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-bounce [animation-delay:240ms]" />
                  </span>
                  {t('chatbot.thinking')}
                </div>
              )}

              {error && (
                <div className="flex items-start gap-2 text-xs text-amber-300 bg-amber-900/30 border border-amber-700/50 rounded px-2 py-1.5">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              {/* Suggestion chips — only when chat is empty */}
              {!welcomeShown && suggestions.length > 0 && (
                <div className="pt-2">
                  <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-1.5">
                    {t('chatbot.suggestions')}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {suggestions.map((s) => (
                      <button
                        key={s}
                        type="button"
                        onClick={() => void send(s)}
                        className="text-xs px-2.5 py-1 rounded-full bg-slate-800 hover:bg-brand-500/20 hover:border-brand-400 border border-slate-700 text-slate-200 transition"
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Input */}
            <form onSubmit={onSubmit} className="border-t border-slate-800 bg-slate-900 p-2">
              <div className="flex items-end gap-2">
                <textarea
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault()
                      void send(input)
                    }
                  }}
                  rows={1}
                  maxLength={2000}
                  placeholder={t('chatbot.placeholder')}
                  className="flex-1 resize-none rounded-md bg-slate-800 border border-slate-700 px-3 py-2 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-brand-400 max-h-32"
                />
                <button
                  type="submit"
                  disabled={pending || !input.trim()}
                  aria-label={t('chatbot.send')}
                  className="h-10 w-10 rounded-md bg-brand-500 hover:bg-brand-400 disabled:bg-slate-700 disabled:text-slate-500 text-white flex items-center justify-center transition"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
              <div className="px-1 pt-1.5 text-[10px] text-slate-500">{t('chatbot.disclaimer')}</div>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}

// ---------------------------------------------------------------------------
// Sub-components.
// ---------------------------------------------------------------------------
function Bubble({
  msg,
  sourceLabel,
  relatedLabel,
}: {
  msg: Message
  sourceLabel: string | null
  relatedLabel: string
}) {
  const isUser = msg.role === 'user'
  return (
    <div className={clsx('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div
        className={clsx(
          'max-w-[88%] rounded-lg px-3 py-2 text-sm leading-relaxed',
          isUser
            ? 'bg-brand-500 text-white rounded-br-sm'
            : 'bg-slate-800 text-slate-100 rounded-bl-sm border border-slate-700',
        )}
      >
        {isUser ? (
          <span className="whitespace-pre-wrap">{msg.text}</span>
        ) : (
          <div className="text-sm leading-relaxed [&_p]:my-1.5 [&_strong]:text-white [&_a]:text-brand-300 [&_a]:underline [&_code]:text-brand-300 [&_code]:bg-slate-900 [&_code]:px-1 [&_code]:rounded [&_ul]:list-disc [&_ul]:ml-4 [&_ol]:list-decimal [&_ol]:ml-4">
            <ReactMarkdown>{msg.text}</ReactMarkdown>
          </div>
        )}

        {!isUser && sourceLabel && (
          <div className="mt-2 pt-1.5 border-t border-slate-700/60 text-[10px] uppercase tracking-wide text-slate-400">
            {sourceLabel}
          </div>
        )}

        {!isUser && msg.related && msg.related.length > 0 && (
          <div className="mt-2 pt-1.5 border-t border-slate-700/60">
            <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-1">{relatedLabel}</div>
            <ul className="space-y-0.5">
              {msg.related.slice(0, 3).map((r) => (
                <li key={r.id} className="text-xs">
                  <a href={`/faq#${r.id}`} className="text-brand-300 hover:text-brand-200 underline-offset-2 hover:underline">
                    {r.question}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}
