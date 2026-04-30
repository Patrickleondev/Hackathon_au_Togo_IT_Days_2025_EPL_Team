import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { Auth } from '@/api/client'

export default function Login() {
  const [email, setEmail] = useState('admin@guardian.local')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setErr(null); setLoading(true)
    try {
      await Auth.login(email, password)
      navigate('/app')
    } catch (e: any) {
      setErr(e.response?.data?.detail || 'Login failed')
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-brand-900 to-brand-700">
      <form onSubmit={onSubmit} className="card w-96 space-y-4">
        <div className="flex items-center gap-2 text-brand-700">
          <Shield /> <h1 className="text-xl font-bold">GuardIAn</h1>
        </div>
        <div>
          <label className="text-sm text-slate-600">Email</label>
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <div>
          <label className="text-sm text-slate-600">Password</label>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        {err && <div className="text-sm text-red-600">{err}</div>}
        <button disabled={loading} className="btn-primary w-full justify-center">
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
