import { useState } from 'react'
import { Activity, Globe2, Loader2, Radar, Search, ShieldAlert, Wifi } from 'lucide-react'
import { Network, type NetworkBeacon, type NetworkStats } from '@/api/client'

function Metric({ label, value, icon: Icon }: { label: string; value: string | number; icon: any }) {
  return (
    <div className="card flex items-center justify-between gap-4">
      <div>
        <div className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">{label}</div>
        <div className="mt-2 text-2xl font-bold text-slate-100">{value}</div>
      </div>
      <div className="rounded border border-blue-900/60 bg-blue-950/30 p-3 text-blue-400">
        <Icon size={22} aria-hidden />
      </div>
    </div>
  )
}

function bestNumber(data: NetworkStats | null, keys: string[], fallback = 0) {
  if (!data) return fallback
  for (const key of keys) {
    const value = data[key]
    if (typeof value === 'number') return value
  }
  return fallback
}

export default function NetworkPage() {
  const [stats, setStats] = useState<NetworkStats | null>(null)
  const [beacons, setBeacons] = useState<NetworkBeacon[]>([])
  const [domain, setDomain] = useState('')
  const [dga, setDga] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function refresh() {
    setLoading(true)
    setError(null)
    try {
      const [networkStats, beaconData] = await Promise.all([
        Network.stats(),
        Network.beacons(0.3, 25),
      ])
      setStats(networkStats)
      setBeacons(beaconData.items)
    } catch (err: any) {
      setError(err.response?.data?.detail || String(err))
    } finally {
      setLoading(false)
    }
  }

  async function scoreDomain(event: React.FormEvent) {
    event.preventDefault()
    if (!domain.trim()) return
    setError(null)
    setDga(null)
    try {
      setDga(await Network.dga(domain.trim()))
    } catch (err: any) {
      setError(err.response?.data?.detail || String(err))
    }
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-700">
      <div className="flex flex-col gap-4 border-b border-slate-800 pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white uppercase flex items-center gap-3">
            <Radar className="text-blue-500" aria-hidden />
            Network Intelligence
          </h1>
          <p className="mt-2 text-sm text-slate-400 font-mono">DGA scoring // JA3 telemetry // beaconing channels</p>
        </div>
        <button onClick={refresh} disabled={loading} className="btn-primary justify-center">
          {loading ? <Loader2 className="mr-2 animate-spin" size={16} aria-hidden /> : <Activity className="mr-2" size={16} aria-hidden />}
          Refresh telemetry
        </button>
      </div>

      {error && (
        <div className="card border-red-900 bg-red-950/20 text-red-300" role="alert">
          <div className="flex items-center gap-2 font-bold uppercase tracking-widest text-xs">
            <ShieldAlert size={16} aria-hidden /> Network module unavailable
          </div>
          <p className="mt-2 text-sm font-mono text-red-200/80">{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Metric label="Events observed" value={bestNumber(stats, ['events', 'event_count', 'total_events'])} icon={Wifi} />
        <Metric label="Beacon candidates" value={beacons.length} icon={Radar} />
        <Metric label="Known indicators" value={bestNumber(stats, ['indicators', 'indicator_count', 'ja3_count'])} icon={Globe2} />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <section className="card space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <h2 className="font-semibold uppercase tracking-widest text-xs text-slate-300">On-demand DGA scoring</h2>
          </div>
          <form onSubmit={scoreDomain} className="flex flex-col gap-3 sm:flex-row">
            <label className="sr-only" htmlFor="domain-score">Domain</label>
            <input
              id="domain-score"
              className="input"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="example-c2-domain[.]com"
            />
            <button className="btn-primary justify-center" disabled={!domain.trim()}>
              <Search size={16} className="mr-2" aria-hidden /> Score
            </button>
          </form>
          {dga && (
            <div className="rounded border border-slate-800 bg-slate-950 p-4 font-mono text-sm text-slate-300">
              <pre className="overflow-auto whitespace-pre-wrap">{JSON.stringify(dga, null, 2)}</pre>
            </div>
          )}
        </section>

        <section className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
            <h2 className="font-semibold uppercase tracking-widest text-xs text-slate-300">Beaconing channels</h2>
            <span className="tag-medium">score &gt;= 0.30</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-slate-500 border-b border-slate-800">
                <tr>
                  <th className="p-2">Source</th>
                  <th>Destination</th>
                  <th>Period</th>
                  <th>Score</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {beacons.map((beacon) => (
                  <tr key={beacon.id} className="border-b border-slate-800 last:border-0 hover:bg-slate-950/70">
                    <td className="p-2 font-mono text-slate-300">{beacon.src_ip}</td>
                    <td className="font-mono text-slate-400">{beacon.dst_ip}:{beacon.dst_port || '-'}</td>
                    <td>{Math.round(beacon.period_s)}s</td>
                    <td>{(beacon.score * 100).toFixed(0)}%</td>
                    <td><span className={beacon.score >= 0.75 ? 'tag-high' : 'tag-medium'}>{beacon.verdict}</span></td>
                  </tr>
                ))}
                {!beacons.length && (
                  <tr><td className="p-6 text-center text-slate-500" colSpan={5}>No beaconing telemetry loaded. Refresh to query the backend.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  )
}