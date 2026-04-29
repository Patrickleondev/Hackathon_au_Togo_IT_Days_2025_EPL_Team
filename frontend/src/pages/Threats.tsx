import { useEffect, useState } from 'react'
import { Threats as T, type Threat } from '@/api/client'

export default function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [busy, setBusy] = useState<string | null>(null)

  const refresh = () => T.list(100).then((d) => setThreats(d.items))
  useEffect(() => { refresh() }, [])

  async function act(id: string, fn: (id: string) => Promise<any>) {
    setBusy(id); try { await fn(id); await refresh() } finally { setBusy(null) }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Threats</h1>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-slate-500 border-b">
            <tr>
              <th className="p-2">Detected</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Source</th>
              <th>File</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((t) => (
              <tr key={t.id} className="border-b last:border-0 hover:bg-slate-50">
                <td className="p-2">{new Date(t.created_at).toLocaleString()}</td>
                <td>{t.threat_type}</td>
                <td><span className={`tag-${t.severity}`}>{t.severity}</span></td>
                <td>{(t.confidence * 100).toFixed(0)}%</td>
                <td className="text-xs text-slate-600">{t.detection_source}</td>
                <td className="font-mono text-xs truncate max-w-xs">{t.file_path}</td>
                <td>{t.status}</td>
                <td className="space-x-2">
                  <button disabled={busy === t.id} className="btn-ghost text-xs" onClick={() => act(t.id, T.quarantine)}>Quarantine</button>
                  <button disabled={busy === t.id} className="btn-ghost text-xs" onClick={() => act(t.id, T.neutralize)}>Neutralize</button>
                  <button disabled={busy === t.id} className="btn-ghost text-xs" onClick={() => act(t.id, T.dismiss)}>Dismiss</button>
                </td>
              </tr>
            ))}
            {!threats.length && (
              <tr><td className="p-4 text-center text-slate-500" colSpan={8}>No threats detected.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
