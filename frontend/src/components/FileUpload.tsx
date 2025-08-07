import React, { useState, useCallback } from 'react';
import { Upload, File, Shield, AlertTriangle, CheckCircle, X, Eye, Download, Trash2, Zap } from 'lucide-react';
import axios from 'axios';

interface FileAnalysis {
  id: string;
  filename: string;
  size: number;
  type: string;
  status: 'pending' | 'analyzing' | 'completed' | 'error';
  threat_detected: boolean;
  confidence: number;
  threat_type?: string;
  severity?: string;
  description?: string;
  recommendations?: string[];
  timestamp: string;
}

const FileUpload: React.FC = () => {
  const [files, setFiles] = useState<File[]>([]);
  const [analyses, setAnalyses] = useState<FileAnalysis[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    setFiles(prev => [...prev, ...droppedFiles]);
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []);
    setFiles(prev => [...prev, ...selectedFiles]);
  };

  const removeFile = (index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const analyzeFiles = async () => {
    if (files.length === 0) return;

    setUploading(true);
    setError(null);

    try {
      const formData = new FormData();
      files.forEach(file => {
        formData.append('files', file);
      });

      const response = await axios.post('/api/analyze/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          // Mise à jour du progrès
          const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1));
          console.log('Progression:', percentCompleted);
        }
      });

      // Traiter les résultats
      const newAnalyses: FileAnalysis[] = files.map((file, index) => ({
        id: `analysis-${Date.now()}-${index}`,
        filename: file.name,
        size: file.size,
        type: file.type,
        status: 'completed',
        threat_detected: response.data.results?.[index]?.is_threat || false,
        confidence: response.data.results?.[index]?.confidence || 0,
        threat_type: response.data.results?.[index]?.threat_type,
        severity: response.data.results?.[index]?.severity,
        description: response.data.results?.[index]?.description,
        recommendations: response.data.results?.[index]?.recommendations || [],
        timestamp: new Date().toISOString()
      }));

      setAnalyses(prev => [...newAnalyses, ...prev]);
      setFiles([]);
    } catch (err) {
      console.error('Erreur lors de l\'analyse:', err);
      setError('Erreur lors de l\'analyse des fichiers');
    } finally {
      setUploading(false);
    }
  };

  const getFileIcon = (type: string) => {
    if (type.startsWith('image/')) return '🖼️';
    if (type.startsWith('video/')) return '🎥';
    if (type.startsWith('audio/')) return '🎵';
    if (type.includes('pdf')) return '📄';
    if (type.includes('word') || type.includes('document')) return '📝';
    if (type.includes('excel') || type.includes('spreadsheet')) return '📊';
    if (type.includes('powerpoint') || type.includes('presentation')) return '📈';
    if (type.includes('zip') || type.includes('rar')) return '📦';
    if (type.includes('exe') || type.includes('executable')) return '⚙️';
    return '📁';
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getThreatColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'text-red-600 bg-red-100 border-red-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-100 border-green-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* En-tête */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Analyse de fichiers</h1>
        <p className="text-gray-600">Analysez vos fichiers avec notre IA de détection avancée</p>
      </div>

      {/* Zone de drag & drop */}
      <div
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 ${
          isDragOver 
            ? 'border-blue-500 bg-blue-50' 
            : 'border-gray-300 hover:border-gray-400'
        }`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          Glissez vos fichiers ici ou cliquez pour sélectionner
        </h3>
        <p className="text-gray-500 mb-4">
          Formats supportés: EXE, PDF, DOC, ZIP, et plus encore
        </p>
        <input
          type="file"
          multiple
          onChange={handleFileSelect}
          className="hidden"
          id="file-input"
          accept="*/*"
        />
        <label
          htmlFor="file-input"
          className="inline-flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors cursor-pointer"
        >
          <File className="w-5 h-5 mr-2" />
          Sélectionner des fichiers
        </label>
      </div>

      {/* Liste des fichiers sélectionnés */}
      {files.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">
              Fichiers sélectionnés ({files.length})
            </h3>
            <button
              onClick={analyzeFiles}
              disabled={uploading}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Zap className="w-4 h-4" />
              <span>{uploading ? 'Analyse en cours...' : 'Analyser les fichiers'}</span>
            </button>
          </div>
          
          <div className="space-y-3">
            {files.map((file, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">{getFileIcon(file.type)}</span>
                  <div>
                    <p className="text-sm font-medium text-gray-900">{file.name}</p>
                    <p className="text-xs text-gray-500">{formatFileSize(file.size)}</p>
                  </div>
                </div>
                <button
                  onClick={() => removeFile(index)}
                  className="text-gray-400 hover:text-red-500 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Résultats d'analyse */}
      {analyses.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Résultats d'analyse</h3>
          
          <div className="space-y-4">
            {analyses.map((analysis) => (
              <div key={analysis.id} className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{getFileIcon(analysis.type)}</span>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{analysis.filename}</p>
                      <p className="text-xs text-gray-500">
                        {formatFileSize(analysis.size)} • {new Date(analysis.timestamp).toLocaleString('fr-FR')}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {analysis.threat_detected ? (
                      <div className="flex items-center space-x-2">
                        <AlertTriangle className="w-5 h-5 text-red-500" />
                        <span className="text-sm font-medium text-red-600">Menace détectée</span>
                      </div>
                    ) : (
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-5 h-5 text-green-500" />
                        <span className="text-sm font-medium text-green-600">Sécurisé</span>
                      </div>
                    )}
                  </div>
                </div>

                {analysis.threat_detected && (
                  <div className="bg-red-50 border border-red-200 rounded-lg p-3 mb-3">
                    <div className="flex items-start space-x-3">
                      <Shield className="w-5 h-5 text-red-500 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getThreatColor(analysis.severity || '')}`}>
                            {analysis.severity || 'Unknown'}
                          </span>
                          <span className="text-sm text-gray-600">
                            Confiance: {analysis.confidence.toFixed(1)}%
                          </span>
                        </div>
                        <p className="text-sm text-gray-900 mb-2">{analysis.description}</p>
                        {analysis.recommendations && analysis.recommendations.length > 0 && (
                          <div>
                            <p className="text-xs font-medium text-gray-700 mb-1">Recommandations:</p>
                            <ul className="text-xs text-gray-600 space-y-1">
                              {analysis.recommendations.map((rec, index) => (
                                <li key={index} className="flex items-start space-x-1">
                                  <span className="text-red-500">•</span>
                                  <span>{rec}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Type: {analysis.threat_type || 'Non détecté'}</span>
                  <span>Analyse terminée</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Statistiques */}
      {analyses.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card text-center">
            <div className="text-2xl font-bold text-blue-600">{analyses.length}</div>
            <div className="text-sm text-gray-600">Fichiers analysés</div>
          </div>
          <div className="card text-center">
            <div className="text-2xl font-bold text-red-600">
              {analyses.filter(a => a.threat_detected).length}
            </div>
            <div className="text-sm text-gray-600">Menaces détectées</div>
          </div>
          <div className="card text-center">
            <div className="text-2xl font-bold text-green-600">
              {analyses.filter(a => !a.threat_detected).length}
            </div>
            <div className="text-sm text-gray-600">Fichiers sécurisés</div>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileUpload; 