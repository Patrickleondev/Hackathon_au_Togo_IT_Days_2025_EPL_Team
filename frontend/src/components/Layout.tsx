import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { Shield, Activity, Server, AlertTriangle, ScanLine, BarChart3, LogOut, Upload } from 'lucide-react'
import { Auth } from '@/api/client'
import InvestigationChat from './InvestigationChat'

export default function Layout() {
  const navigate = useNavigate()
  const items = [
    { to: '/app', label: 'Dashboard', icon: Activity, end: true },
    { to: '/app/threats', label: 'Threats', icon: AlertTriangle },
    { to: '/app/agents', label: 'Agents', icon: Server },
    { to: '/app/analyze', label: 'Analyze', icon: Upload },
    { to: '/app/scans', label: 'Scans', icon: ScanLine },
    { to: '/app/stats', label: 'Statistics', icon: BarChart3 },
  ]
  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-200 font-sans">
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="p-5 border-b border-slate-800 flex items-center gap-3">
          <Shield className="text-blue-500" size={24} />
          <span className="font-bold tracking-wide text-lg text-slate-100 uppercase">GuardIAn SOC</span>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {items.map((it) => (
            <NavLink
              key={it.to}
              to={it.to}
              end={it.end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-md font-medium text-sm transition-colors ${
                  isActive 
                    ? 'bg-blue-900/30 text-blue-400 border-l-2 border-blue-500' 
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 border-l-2 border-transparent'
                }`
              }
            >
              <it.icon size={18} />
              <span>{it.label}</span>
            </NavLink>
          ))}
        </nav>
        <button
          onClick={() => { Auth.logout(); navigate('/login') }}
          className="m-4 flex items-center gap-2 px-3 py-2 rounded-md bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700 transition"
        >
          <LogOut size={16} /> Sign out
        </button>
      </aside>
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
      
      {/* Bot d'investigation flottant SOC */}
      <InvestigationChat />
    </div>
  )
}
