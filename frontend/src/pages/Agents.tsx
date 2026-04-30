import { useEffect, useState } from 'react'
import { Agents as A, type Agent } from '@/api/client'

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([])
  useEffect(() => { A.list().then(setAgents) }, [])
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Agents</h1>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-slate-500 border-b">
            <tr>
              <th className="p-2">Hostname</th>
              <th>OS</th>
              <th>Version</th>
              <th>Last seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.id} className="border-b last:border-0">
                <td className="p-2 font-medium">{a.hostname}</td>
                <td>{a.os} {a.os_version}</td>
                <td>{a.agent_version || '—'}</td>
                <td>{a.last_seen_at ? new Date(a.last_seen_at).toLocaleString() : 'never'}</td>
                <td>
                  <span className={`tag-${a.is_active ? 'low' : 'high'}`}>
                    {a.is_active ? 'active' : 'inactive'}
                  </span>
                </td>
              </tr>
            ))}
            {!agents.length && (
              <tr><td className="p-4 text-center text-slate-500" colSpan={5}>No agents registered.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
