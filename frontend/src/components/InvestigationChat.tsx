import React, { useState, useRef, useEffect } from 'react'
import { MessageSquare, X, Send, Command, Loader2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { Assistant } from '@/api/client'

type Message = {
  id: string
  role: 'user' | 'system'
  text: string
  isCommand?: boolean
}

export default function InvestigationChat() {
  const { i18n } = useTranslation()
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState<Message[]>([
    { id: '1', role: 'system', text: 'Security Operations Center - Investigation Terminal active. Ask about deployment, detection, agents, network telemetry, or the ML pipeline.' }
  ])
  const [isTyping, setIsTyping] = useState(false)
  const endOfMessagesRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (endOfMessagesRef.current) {
      endOfMessagesRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages])

  useEffect(() => {
    if (!isOpen) return
    const timer = window.setTimeout(() => inputRef.current?.focus(), 80)
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setIsOpen(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.clearTimeout(timer)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [isOpen])

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return

    const userMsg: Message = { id: Date.now().toString(), role: 'user', text: query, isCommand: query.startsWith('/') }
    setMessages(prev => [...prev, userMsg])
    setQuery('')
    setIsTyping(true)

    try {
      const lang = (i18n.resolvedLanguage || i18n.language || 'fr').startsWith('en') ? 'en' : 'fr'
      const reply = await Assistant.send(userMsg.text, lang)
      const source = reply.source === 'llm' && reply.provider ? ` // ${reply.provider}` : ` // ${reply.source.toUpperCase()}`
      setMessages(prev => [...prev, {
        id: (Date.now() + 1).toString(),
        role: 'system',
        text: `${reply.text}${source}`
      }])
    } catch (error: any) {
      const detail = error.response?.data?.detail || 'Error connecting to Command Module.'
      setMessages(prev => [...prev, { id: Date.now().toString(), role: 'system', text: String(detail) }])
    } finally {
      setIsTyping(false)
    }
  }

  return (
    <>
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 p-4 rounded-full bg-blue-600 text-white shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-300 focus:ring-offset-2 focus:ring-offset-slate-950 hover:bg-blue-700 transition z-50"
          title="Open Investigation Terminal"
          aria-label="Open SOC investigation terminal"
        >
          <MessageSquare size={24} aria-hidden />
        </button>
      )}

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 50, scale: 0.95 }}
            className="fixed bottom-4 right-4 md:bottom-6 md:right-6 w-[min(calc(100vw-2rem),28rem)] h-[min(560px,calc(100vh-2rem))] flex flex-col bg-slate-900 border border-slate-700 shadow-2xl rounded-lg overflow-hidden z-50 text-slate-300 font-mono text-sm"
            role="dialog"
            aria-modal="false"
            aria-label="SOC investigation terminal"
          >
            {/* Header */}
            <div className="bg-slate-950 border-b border-slate-800 p-3 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <Command size={16} className="text-blue-500" aria-hidden />
                <span className="font-semibold text-slate-100 tracking-wider">SOC Terminal</span>
              </div>
              <button onClick={() => setIsOpen(false)} className="text-slate-400 hover:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-400 rounded" aria-label="Close SOC terminal">
                <X size={18} aria-hidden />
              </button>
            </div>

            {/* Chat Body */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((msg) => (
                <div key={msg.id} className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
                  <div className={`px-3 py-2 rounded max-w-[85%] ${
                    msg.role === 'user' 
                      ? 'bg-blue-900/40 text-blue-100 border border-blue-800/50' 
                      : 'bg-slate-800/50 text-slate-300 border border-slate-700'
                  }`}>
                    {msg.isCommand && <span className="text-blue-400 mr-2">&gt;</span>}
                    {msg.text}
                  </div>
                </div>
              ))}
              {isTyping && (
                <div className="flex items-start">
                  <div className="px-3 py-2 rounded bg-slate-800/50 border border-slate-700 flex items-center gap-2">
                    <Loader2 size={14} className="animate-spin text-blue-500" />
                    <span>Processing...</span>
                  </div>
                </div>
              )}
              <div ref={endOfMessagesRef} />
            </div>

            {/* Input Footer */}
            <form onSubmit={handleSend} className="p-3 bg-slate-950 border-t border-slate-800 flex gap-2">
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Ex: /scan 192.168.1.10 or ask a question..."
                className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
                aria-label="SOC assistant message"
              />
              <button 
                type="submit" 
                disabled={!query.trim() || isTyping}
                className="bg-blue-600 hover:bg-blue-700 p-2 rounded text-white flex-shrink-0 disabled:opacity-50 transition-colors"
                aria-label="Send message"
              >
                <Send size={16} aria-hidden />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
