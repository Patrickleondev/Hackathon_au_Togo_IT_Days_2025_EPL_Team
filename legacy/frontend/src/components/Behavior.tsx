import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, AlertTriangle, Cpu, Network, FileText } from 'lucide-react';

interface BehaviorItem {
  process_name: string;
  pid: number;
  network_behavior: number;
  file_behavior: number;
  resource_usage: { cpu: number; memory: number };
  suspicious_indicators: string[];
}

const Behavior: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<BehaviorItem[]>([]);
  const [lastAnalysis, setLastAnalysis] = useState<string | null>(null);

  const load = async () => {
    try {
      setError(null);
      const res = await axios.get('/api/monitoring/behavior');
      const data = res.data?.data;
      setItems(data?.behavior_analysis || []);
      setLastAnalysis(data?.last_analysis || null);
    } catch (e: any) {
      setError(e?.message || 'Erreur chargement');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="text-blue-600" />
          <h1 className="text-2xl font-bold">Analyse de comportement</h1>
        </div>
        {lastAnalysis && (
          <span className="text-sm text-gray-500">Dernière analyse: {new Date(lastAnalysis).toLocaleTimeString()}</span>
        )}
      </div>

      {loading && <div className="text-gray-500">Chargement...</div>}
      {error && <div className="text-red-600">{error}</div>}

      {!loading && items.length === 0 && (
        <div className="p-4 bg-gray-50 border rounded">Aucun comportement suspect détecté.</div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {items.map((b, idx) => (
          <div key={idx} className="border rounded-lg p-4 bg-white shadow-sm">
            <div className="flex items-center justify-between">
              <div className="font-semibold">{b.process_name} <span className="text-gray-500">(PID {b.pid})</span></div>
              {b.suspicious_indicators.length > 0 && (
                <span className="inline-flex items-center gap-1 text-amber-700 text-sm">
                  <AlertTriangle className="w-4 h-4" /> {b.suspicious_indicators.length} indicateurs
                </span>
              )}
            </div>
            <div className="mt-3 grid grid-cols-3 gap-3 text-sm">
              <div className="flex items-center gap-2"><Cpu className="w-4 h-4" /> CPU: {Math.round(b.resource_usage.cpu)}%</div>
              <div className="flex items-center gap-2"><Cpu className="w-4 h-4" /> RAM: {Math.round(b.resource_usage.memory)}%</div>
              <div className="flex items-center gap-2"><Network className="w-4 h-4" /> Connexions: {b.network_behavior}</div>
            </div>
            <div className="mt-2 text-sm flex items-center gap-2"><FileText className="w-4 h-4" /> Fichiers ouverts: {b.file_behavior}</div>

            {b.suspicious_indicators.length > 0 && (
              <div className="mt-3">
                <div className="text-sm font-medium text-gray-700 mb-1">Indicateurs</div>
                <div className="flex flex-wrap gap-2">
                  {b.suspicious_indicators.map((s, i) => (
                    <span key={i} className="px-2 py-1 rounded bg-amber-50 text-amber-800 text-xs border border-amber-200">{s}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Behavior;