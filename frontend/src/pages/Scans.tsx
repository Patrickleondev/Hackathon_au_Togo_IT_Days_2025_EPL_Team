import { useState } from 'react'
import { Scans } from '@/api/client'

export default function ScansPage() {
  const [type, setType] = useState('quick')
  const [paths, setPaths] = useState('')
  const [scan, setScan] = useState<any>(null)
  const [busy, setBusy] = useState(false)

  async function start() {
    setBusy(true)
    try {
      const targets = paths.split(',').map((s) => s.trim()).filter(Boolean)
      const r = await Scans.start(type, targets)
      setScan(r)
      // Poll every 2s for 30s max
      let i = 0
      const t = setInterval(async () => {
        try { setScan(await Scans.get(r.id)) } catch {}
        if (++i > 15) clearInterval(t)
      }, 2000)
    } finally { setBusy(false) }
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-2xl font-bold">Scans</h1>
      <div className="card space-y-3">
        <div>
          <label className="text-sm text-slate-600">Type</label>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            <option value="quick">Quick</option>
            <option value="full">Full</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div>
          <label className="text-sm text-slate-600">Target paths (comma-separated, server-side, defaults to uploads dir)</label>
          <input className="input" value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="/var/lib/ransomguard/uploads" />
        </div>
        <button className="btn-primary" disabled={busy} onClick={start}>Start scan</button>
      </div>
      {scan && (
        <div className="card text-sm space-y-1">
          <div>ID: <code>{scan.id}</code></div>
          <div>Status: <strong>{scan.status}</strong></div>
          <div>Files scanned: {scan.files_scanned}</div>
          <div>Threats found: {scan.threats_found}</div>
          {scan.error && <div className="text-red-600">Error: {scan.error}</div>}
        </div>
      )}
    </div>
  )
}
