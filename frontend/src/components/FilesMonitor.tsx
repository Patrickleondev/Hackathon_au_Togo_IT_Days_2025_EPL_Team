import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { HardDrive, FolderPlus, RefreshCw } from 'lucide-react';

interface DirectoryInfo {
  path: string;
  name: string;
  total_files: number;
  suspicious_files: number;
  last_scan: string;
}

interface FilesMonitoringData {
  monitoring_active: boolean;
  directories_monitored: number;
  total_files_scanned: number;
  suspicious_files: number;
  monitored_directories: string[];
  directories: DirectoryInfo[];
  recent_operations: any[];
  last_scan: string;
}

const FilesMonitor: React.FC = () => {
  const [data, setData] = useState<FilesMonitoringData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newDir, setNewDir] = useState('');
  const [adding, setAdding] = useState(false);

  const load = async () => {
    try {
      setError(null);
      const res = await axios.get('/api/monitoring/files');
      setData(res.data?.data || null);
    } catch (e: any) {
      setError(e?.message || 'Erreur chargement');
    } finally {
      setLoading(false);
    }
  };

  const addDirectory = async () => {
    if (!newDir.trim()) return;
    try {
      setAdding(true);
      await axios.post('/api/monitoring/files/add-directory', null, { params: { directory_path: newDir.trim() } });
      setNewDir('');
      await load();
    } catch (e: any) {
      setError(e?.response?.data?.message || e?.message || 'Erreur ajout répertoire');
    } finally {
      setAdding(false);
    }
  };

  const scanDirectory = async () => {
    if (!newDir.trim()) return;
    try {
      setAdding(true);
      await axios.post('/api/monitoring/files/scan-directory', null, { params: { directory_path: newDir.trim() } });
      await load();
    } catch (e: any) {
      setError(e?.response?.data?.message || e?.message || 'Erreur scan répertoire');
    } finally {
      setAdding(false);
    }
  };

  const quarantine = async (filePath: string) => {
    try {
      await axios.post('/api/monitoring/files/quarantine-file', null, { params: { file_path: filePath } });
      await load();
    } catch (e: any) {
      setError(e?.response?.data?.message || e?.message || 'Erreur quarantaine');
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
          <HardDrive className="text-blue-600" />
          <h1 className="text-2xl font-bold">Surveillance des fichiers</h1>
        </div>
        <button onClick={load} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm border rounded hover:bg-gray-50">
          <RefreshCw className="w-4 h-4" /> Rafraîchir
        </button>
      </div>

      <div className="flex items-center gap-2">
        <input
          type="text"
          value={newDir}
          onChange={(e) => setNewDir(e.target.value)}
          placeholder="Chemin absolu du dossier (ex: /home/user/Documents)"
          className="w-full px-3 py-2 border rounded"
        />
        <button disabled={adding} onClick={addDirectory} className="inline-flex items-center gap-2 px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
          <FolderPlus className="w-4 h-4" /> Ajouter
        </button>
      </div>

      {loading && <div className="text-gray-500">Chargement...</div>}
      {error && <div className="text-red-600">{error}</div>}

      {data && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="border rounded p-4 bg-white">
              <div className="text-sm text-gray-500">Répertoires surveillés</div>
              <div className="text-2xl font-bold">{data.directories_monitored}</div>
            </div>
            <div className="border rounded p-4 bg-white">
              <div className="text-sm text-gray-500">Fichiers scannés</div>
              <div className="text-2xl font-bold">{data.total_files_scanned}</div>
            </div>
            <div className="border rounded p-4 bg-white">
              <div className="text-sm text-gray-500">Fichiers suspects</div>
              <div className="text-2xl font-bold text-amber-700">{data.suspicious_files}</div>
            </div>
          </div>

          <div className="border rounded bg-white">
            <div className="border-b p-3 font-semibold">Répertoires</div>
            <div className="divide-y">
              {(data.directories || []).map((d, i) => (
                <div key={i} className="p-3 flex items-center justify-between">
                  <div>
                    <div className="font-medium">{d.name}</div>
                    <div className="text-sm text-gray-500">{d.path}</div>
                  </div>
                  <div className="text-sm text-gray-600">{d.total_files} fichiers, {d.suspicious_files} suspects</div>
                </div>
              ))}
              {(!data.directories || data.directories.length === 0) && (
                <div className="p-3 text-gray-500">Aucun répertoire surveillé. Ajoutez-en un ci-dessus.</div>
              )}
            </div>
          </div>

          <div className="border rounded bg-white">
            <div className="border-b p-3 font-semibold flex items-center justify-between">
              <span>Événements récents</span>
              <div className="flex items-center gap-2">
                <button onClick={scanDirectory} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm border rounded hover:bg-gray-50" disabled={adding}>
                  Scanner le dossier
                </button>
              </div>
            </div>
            <div className="divide-y">
              {(data.recent_operations || []).slice(0, 20).map((op: any, i: number) => (
                <div key={i} className="p-3 text-sm flex items-center justify-between">
                  <div>
                    <span className="font-medium">{op.operation_type}</span> - {op.file_path}
                    <span className="text-gray-500"> • {new Date(op.timestamp).toLocaleTimeString()}</span>
                  </div>
                  {op.is_suspicious && (
                    <button onClick={() => quarantine(op.file_path)} className="px-2 py-1 text-xs bg-red-600 text-white rounded">
                      Mettre en quarantaine
                    </button>
                  )}
                </div>
              ))}
              {(!data.recent_operations || data.recent_operations.length === 0) && (
                <div className="p-3 text-gray-500">Aucun événement pour le moment.</div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FilesMonitor;