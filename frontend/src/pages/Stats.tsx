import { useEffect, useState } from 'react'
import { api } from '@/api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

export default function StatsPage() {
  const [data, setData] = useState<any>(null)
  useEffect(() => { api.get('/stats').then((r) => setData(r.data)) }, [])

  if (!data) return <div className="card">Loading…</div>
  const breakdown = Object.entries(data.severity_breakdown).map(([k, v]) => ({ severity: k, count: v }))

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Statistics</h1>
      <div className="card">
        <h2 className="font-semibold mb-2">Severity breakdown</h2>
        <div style={{ width: '100%', height: 300 }}>
          <ResponsiveContainer>
            <BarChart data={breakdown}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="severity" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="count" fill="#4f46e5" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="card text-sm">
        <pre className="bg-slate-50 p-4 rounded overflow-auto">{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  )
}
