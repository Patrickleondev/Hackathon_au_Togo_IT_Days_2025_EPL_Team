import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

export const api = axios.create({
  baseURL: `${API_URL}/api`,
  timeout: 20000,
})

const TOKEN_KEY = 'rg_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}
export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

api.interceptors.request.use((config) => {
  const tok = getToken()
  if (tok) config.headers.Authorization = `Bearer ${tok}`
  return config
})

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      clearToken()
      if (location.pathname !== '/login') location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ─── Typed helpers ────────────────────────────────────────────────────────
export interface Threat {
  id: string
  threat_type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  status: string
  confidence: number
  file_path?: string | null
  description?: string | null
  detection_source: string
  created_at: string
  indicators?: Record<string, any>
}

export interface SystemStatus {
  version: string
  threats_detected: number
  agents_online: number
  files_scanned_24h: number
  cpu_usage: number
  memory_usage: number
  disk_usage: number
  detector_ready: boolean
}

export interface Agent {
  id: string
  hostname: string
  os: string
  os_version: string
  agent_version: string
  last_seen_at: string | null
  is_active: boolean
}

export const Auth = {
  async login(email: string, password: string) {
    const form = new URLSearchParams({ username: email, password })
    const r = await api.post('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    setToken(r.data.access_token)
    return r.data
  },
  logout() {
    clearToken()
    location.href = '/login'
  },
  async me() {
    return (await api.get('/auth/me')).data
  },
}

export const Status = {
  async system(): Promise<SystemStatus> {
    return (await api.get('/status')).data
  },
  async stats() {
    return (await api.get('/stats')).data
  },
}

export const Threats = {
  async list(limit = 50): Promise<{ items: Threat[]; count: number }> {
    return (await api.get(`/threats?limit=${limit}`)).data
  },
  async quarantine(id: string) {
    return (await api.post(`/threats/${id}/quarantine`)).data
  },
  async neutralize(id: string) {
    return (await api.post(`/threats/${id}/neutralize`)).data
  },
  async dismiss(id: string) {
    return (await api.post(`/threats/${id}/dismiss`)).data
  },
}

export const Agents = {
  async list(): Promise<Agent[]> {
    return (await api.get('/agents')).data
  },
}

export const Analyze = {
  async file(f: File) {
    const fd = new FormData()
    fd.append('file', f)
    return (await api.post('/analyze/file', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })).data
  },
}

export const Scans = {
  async start(scan_type: string, target_paths: string[] = []) {
    return (await api.post('/scans', { scan_type, target_paths })).data
  },
  async get(id: string) {
    return (await api.get(`/scans/${id}`)).data
  },
}

// ─── Assistant / chatbot ──────────────────────────────────────────────────
export interface RelatedFAQ {
  id: string
  category: string
  question: string
  answer: string
  score?: number | null
}

export interface ChatReply {
  text: string
  lang: 'fr' | 'en'
  source: 'kb' | 'llm' | 'fallback'
  provider?: string | null
  confidence: number
  related: RelatedFAQ[]
}

export interface FAQItem {
  id: string
  category: string
  question: string
  answer: string
}

export interface AssistantProviderInfo {
  configured: boolean
  provider: string
  model?: string | null
}

// Public chat endpoints — auth-free, so we bypass the bearer interceptor by
// using a bare axios call against the same base URL.
export const Assistant = {
  async send(message: string, lang: 'fr' | 'en'): Promise<ChatReply> {
    return (await api.post('/chat', { message, lang })).data
  },
  async faq(lang: 'fr' | 'en'): Promise<FAQItem[]> {
    return (await api.get(`/chat/faq?lang=${lang}`)).data
  },
  async suggestions(lang: 'fr' | 'en'): Promise<string[]> {
    return (await api.get(`/chat/suggestions?lang=${lang}`)).data
  },
  async provider(): Promise<AssistantProviderInfo> {
    return (await api.get('/chat/provider')).data
  },
}
