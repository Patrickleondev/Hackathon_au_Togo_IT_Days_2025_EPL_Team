import React, { useState, useRef, useEffect } from 'react'
import { MessageSquareTerminal, X, Send, Command, Loader2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '@/api/client'

type Message = {
  id: string
  role: 'user' | 'system'
  text: string
  isCommand?: boolean
}

export default function InvestigationChat() {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [messages, setMessages] = useState<Message[]>([
    { id: '1', role: 'system', text: 'Security Operations Center - Investigation Terminal active. Type a command or ask a question.' }
  ])
  const [isTyping, setIsTyping] = useState(false)
  const endOfMessagesRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (endOfMessagesRef.current) {
      endOfMessagesRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages])

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return

    const userMsg: Message = { id: Date.now().toString(), role: 'user', text: query, isCommand: query.startsWith('/') }
    setMessages(prev => [...prev, userMsg])
    setQuery('')
    setIsTyping(true)

    try {
      // Future integration: Replace with a specific endpoint like POST /api/v1/investigate
      // For now, simulating the AI/SOC NLP interaction to avoid breaking existing backend.
      setTimeout(() => {
        setMessages(prev => [...prev, { 
          id: (Date.now() + 1).toString(), 
          role: 'system', 
          text: `Command received. NLP analysis running for: "${userMsg.text}". Endpoint analysis queued.` 
        }])
        setIsTyping(false)
      }, 1000)
    } catch (error) {
      setMessages(prev => [...prev, { id: Date.now().toString(), role: 'system', text: 'Error connecting to Command Module.' }])
      setIsTyping(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 p-4 rounded-full bg-blue-600 text-white shadow-lg focus:outline-none hover:bg-blue-700 transition"
        title="Open Investigation Terminal"
      >
        <MessageSquareTerminal size={24} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 50, scale: 0.95 }}
            className="fixed bottom-6 right-6 w-96 h-[500px] flex flex-col bg-slate-900 border border-slate-700 shadow-2xl rounded-lg overflow-hidden z-50 text-slate-300 font-mono text-sm"
          >
            {/* Header */}
            <div className="bg-slate-950 border-b border-slate-800 p-3 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <Command size={16} className="text-blue-500" />
                <span className="font-semibold text-slate-100 tracking-wider">SOC Terminal</span>
              </div>
              <button onClick={() => setIsOpen(false)} className="text-slate-400 hover:text-slate-100">
                <X size={18} />
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
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Ex: /scan 192.168.1.10 or ask a question..."
                className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
                autoFocus
              />
              <button 
                type="submit" 
                disabled={!query.trim() || isTyping}
                className="bg-blue-600 hover:bg-blue-700 p-2 rounded text-white flex-shrink-0 disabled:opacity-50 transition-colors"
              >
                <Send size={16} />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
