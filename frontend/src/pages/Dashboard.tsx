import { useEffect, useState } from 'react'
import { Status, type SystemStatus } from '@/api/client'
import { Activity, Cpu, MemoryStick, HardDrive, AlertTriangle, Server } from 'lucide-react'

function Stat({ icon: Icon, label, value, color = 'text-brand-600' }: any) {
  return (
    <div className="card flex items-center gap-4">
      <div className={`p-3 rounded-lg bg-brand-50 ${color}`}><Icon /></div>
      <div>
        <div className="text-sm text-slate-500">{label}</div>
        <div className="text-2xl font-bold">{value}</div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [s, setS] = useState<SystemStatus | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    const fetch = () => Status.system().then((d) => alive && setS(d)).catch((e) => setErr(String(e)))
    fetch()
    const i = setInterval(fetch, 5000)
    return () => { alive = false; clearInterval(i) }
  }, [])

  if (err) return <div className="card text-red-600">{err}</div>
  if (!s) return <div className="card">Loading…</div>

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Overview</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat icon={AlertTriangle} label="Threats (24h)" value={s.threats_detected} color="text-red-600" />
        <Stat icon={Server} label="Agents online" value={s.agents_online} />
        <Stat icon={Activity} label="Files scanned (24h)" value={s.files_scanned_24h} />
        <Stat icon={Cpu} label="CPU" value={`${s.cpu_usage.toFixed(1)} %`} />
        <Stat icon={MemoryStick} label="Memory" value={`${s.memory_usage.toFixed(1)} %`} />
        <Stat icon={HardDrive} label="Disk" value={`${s.disk_usage.toFixed(1)} %`} />
      </div>
      <div className="card">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">Detector</h2>
          <span className={`tag-${s.detector_ready ? 'low' : 'high'}`}>
            {s.detector_ready ? 'Ready' : 'Heuristic-only (no model)'}
          </span>
        </div>
        <p className="text-sm text-slate-600 mt-2">
          Version <code>{s.version}</code> — heuristic + ML + YARA pipeline.
        </p>
      </div>
    </div>
  )
}
