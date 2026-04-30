import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { Shield, Activity, Server, AlertTriangle, ScanLine, BarChart3, LogOut, Upload } from 'lucide-react'
import { Auth } from '@/api/client'

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
    <div className="min-h-screen flex">
      <aside className="w-64 bg-brand-900 text-white flex flex-col">
        <div className="p-5 border-b border-brand-700 flex items-center gap-2">
          <Shield className="text-brand-100" />
          <span className="font-semibold text-lg">GuardIAn</span>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {items.map((it) => (
            <NavLink
              key={it.to}
              to={it.to}
              end={it.end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg transition ${
                  isActive ? 'bg-brand-700' : 'hover:bg-brand-700/60'
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
          className="m-4 flex items-center gap-2 px-3 py-2 rounded-lg bg-brand-700 hover:bg-brand-600"
        >
          <LogOut size={18} /> Sign out
        </button>
      </aside>
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
