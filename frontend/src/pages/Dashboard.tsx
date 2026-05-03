import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Status, type SystemStatus } from '@/api/client'
import { Activity, Cpu, MemoryStick, HardDrive, AlertTriangle, Server, ShieldAlert, Search } from 'lucide-react'

function Stat({ icon: Icon, label, value, colorClass = 'text-blue-500', bgClass = 'bg-blue-900/30' }: any) {
  return (
    <div className="card flex items-center gap-4 relative overflow-hidden group border-slate-800">
      <div className={`absolute -right-4 -top-4 w-24 h-24 ${bgClass} rounded-full blur-[30px] opacity-20 group-hover:opacity-50 transition-opacity duration-700`}></div>
      <div className={`p-4 rounded border border-slate-700/50 ${bgClass} ${colorClass} z-10`}>
        <Icon size={24} />
      </div>
      <div className="z-10">
        <div className="text-[10px] uppercase tracking-widest font-bold text-slate-500">{label}</div>
        <div className={`text-2xl font-bold tracking-tight ${colorClass}`}>{value}</div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [s, setS] = useState<SystemStatus | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    const fetch = () => Status.system().then((d) => {
      if(alive){ setS(d); setErr(null) }
    }).catch((e) => {
      if(alive) setErr(String(e))
    })
    fetch()
    const i = setInterval(fetch, 5000)
    return () => { alive = false; clearInterval(i) }
  }, [])

  if (err) return (
    <div className="card border-red-900 bg-red-900/10 text-red-500 flex items-center gap-3">
      <AlertTriangle className="animate-pulse" />
      <div>
        <h3 className="font-bold uppercase tracking-wider text-sm">System Telemetry Disconnected</h3>
        <p className="text-xs font-mono opacity-80 mt-1">{err}</p>
      </div>
    </div>
  )
  
  if (!s) return (
    <div className="card border-slate-800 flex items-center justify-center py-32 text-slate-500 gap-3">
      <Activity className="animate-spin text-blue-500" />
      <span className="uppercase tracking-widest text-sm font-semibold">Initializing SOC Uplink...</span>
    </div>
  )

  return (
    <div className="space-y-6 animate-in fade-in duration-700">
      <div className="flex items-end justify-between border-b border-slate-800 pb-6 mb-8 mt-2">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white uppercase flex items-center gap-3">
             <ShieldAlert className="text-blue-500" />
             SOC Command Center
          </h1>
          <p className="text-sm text-slate-400 mt-2 font-mono tracking-tight">LIVE TELEMETRY // ASSET INTELLIGENCE v{s.version}</p>
        </div>
        <div className="flex items-center gap-3 bg-slate-900 px-4 py-2 rounded border border-slate-800">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-[10px] uppercase tracking-widest font-bold text-emerald-500">System Online</span>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <Stat icon={AlertTriangle} label="Threats detected (24h)" value={s.threats_detected} colorClass="text-red-500" bgClass="bg-red-900/30" />
        <Stat icon={Server} label="Agents Online" value={s.agents_online} colorClass="text-emerald-400" bgClass="bg-emerald-900/30" />
        <Stat icon={Search} label="Files Scanned (24h)" value={s.files_scanned_24h.toLocaleString()} colorClass="text-blue-400" bgClass="bg-blue-900/30" />
        <Stat icon={Cpu} label="Global CPU Load" value={`${s.cpu_usage.toFixed(1)}%`} colorClass={s.cpu_usage > 80 ? 'text-orange-500' : 'text-slate-300'} bgClass="bg-slate-800/50" />
        <Stat icon={MemoryStick} label="Memory Usage" value={`${s.memory_usage.toFixed(1)}%`} colorClass={s.memory_usage > 80 ? 'text-orange-500' : 'text-slate-300'} bgClass="bg-slate-800/50" />
        <Stat icon={HardDrive} label="Disk I/O" value={`${s.disk_usage.toFixed(1)}%`} colorClass={s.disk_usage > 90 ? 'text-red-500' : 'text-slate-300'} bgClass="bg-slate-800/50" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-8">
        <div className="card">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <h2 className="font-semibold uppercase tracking-widest text-xs flex items-center gap-2 text-slate-300">
              <Activity size={16} className="text-blue-500" /> Pipeline Detection Engine
            </h2>
            <span className={`tag-${s.detector_ready ? 'low' : 'high'}`}>
              {s.detector_ready ? 'ENGAGED & ACTIVE' : 'HEURISTIC FALLBACK'}
            </span>
          </div>
          <div className="space-y-4">
            <div className="bg-slate-950 p-4 rounded border border-slate-800 font-mono text-[13px] leading-relaxed">
              <p className="text-slate-500 mb-2">// System Integrity Check</p>
              <p className="text-emerald-400">&gt; Core Heuristics Analysis ........... [OK]</p>
              {s.detector_ready ? (
                <p className="text-emerald-400">&gt; Multi-Layer ML Inference ........... [OK]</p>
              ) : (
                <p className="text-orange-400">&gt; ML Models Offline .................. [WARN]</p>
              )}
              <p className="text-emerald-400">&gt; Thread Injection Monitoring ........ [OK]</p>
              <p className="text-emerald-400">&gt; Network Signatures (YARA) .......... [OK]</p>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              The Security Operations Center is continuously processing telemetry and signals from active agents across the infrastructure.
            </p>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <h2 className="font-semibold uppercase tracking-widest text-xs text-slate-300">Live Operations</h2>
          </div>
          <div className="space-y-3">
             <button onClick={() => navigate('/app/scans')} className="w-full text-left bg-slate-950 hover:bg-slate-900 border border-slate-800 p-4 rounded flex items-center justify-between transition group">
               <div>
                  <div className="text-sm font-bold text-slate-200 group-hover:text-blue-400 transition">Force Global Sweep</div>
                  <div className="text-[11px] tracking-widest text-slate-500 uppercase mt-1">Initiates behavior signature matches on all agents</div>
               </div>
               <Activity size={18} className="text-slate-700 group-hover:text-blue-500" />
             </button>
             <button onClick={() => navigate('/app/network')} className="w-full text-left bg-slate-950 hover:bg-slate-900 border border-slate-800 p-4 rounded flex items-center justify-between transition group">
               <div>
                  <div className="text-sm font-bold text-slate-200 group-hover:text-blue-400 transition">Update Threat Intel</div>
                  <div className="text-[11px] tracking-widest text-slate-500 uppercase mt-1">Inspect DGA, JA3 and beaconing telemetry</div>
               </div>
               <MemoryStick size={18} className="text-slate-700 group-hover:text-blue-500" />
             </button>
          </div>
        </div>
      </div>
    </div>
  )
}
