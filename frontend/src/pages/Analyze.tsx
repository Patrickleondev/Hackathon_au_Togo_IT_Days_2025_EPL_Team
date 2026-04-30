import { useState } from 'react'
import { Analyze } from '@/api/client'
import { Upload, Loader2 } from 'lucide-react'

export default function AnalyzePage() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [err, setErr] = useState<string | null>(null)

  async function submit() {
    if (!file) return
    setLoading(true); setErr(null); setResult(null)
    try { setResult(await Analyze.file(file)) }
    catch (e: any) { setErr(e.response?.data?.detail || String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-4 max-w-3xl">
      <h1 className="text-2xl font-bold">File Analysis</h1>
      <div className="card space-y-4">
        <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} className="block" />
        <button onClick={submit} disabled={!file || loading} className="btn-primary">
          {loading ? <Loader2 className="animate-spin mr-2" size={16} /> : <Upload size={16} className="mr-2" />}
          Analyze
        </button>
        {err && <div className="text-red-600 text-sm">{err}</div>}
      </div>
      {result && (
        <div className="card space-y-2">
          <div className="flex items-center gap-3">
            <span className={`tag-${result.severity}`}>{result.severity}</span>
            <span className={`tag-${result.is_threat ? 'high' : 'low'}`}>
              {result.is_threat ? 'THREAT' : 'CLEAN'}
            </span>
            <span>Confidence: {(result.confidence * 100).toFixed(1)}%</span>
          </div>
          <div className="text-sm">{result.description}</div>
          <details className="text-xs">
            <summary className="cursor-pointer">Full indicators</summary>
            <pre className="bg-slate-50 rounded p-3 overflow-auto">{JSON.stringify(result, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  )
}
