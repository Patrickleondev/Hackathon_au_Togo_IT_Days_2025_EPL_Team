import React, { useState } from 'react';
import { Upload, File, AlertTriangle, CheckCircle, Clock, Shield } from 'lucide-react';
import axios from 'axios';

interface FileAnalysisResult {
  is_threat: boolean;
  confidence: number;
  risk_level: string;
  final_score: number;
  recommendations: string[];
  analysis_method: string;
  timestamp: string;
}

const FileUpload: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<FileAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
      setAnalysisResult(null);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
      setAnalysisResult(null);
    }
  };

  const analyzeFile = async () => {
    if (!selectedFile) return;

    try {
      setIsAnalyzing(true);
      setError(null);

      // Créer un FormData pour l'upload
      const formData = new FormData();
      formData.append('file', selectedFile);

      // Envoyer le fichier pour analyse
      const response = await axios.post('/api/analyze/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setAnalysisResult(response.data.analysis);
      
    } catch (err: any) {
      console.error('Erreur lors de l\'analyse:', err);
      setError(err.response?.data?.detail || 'Erreur lors de l\'analyse du fichier');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'high':
        return 'text-red-600 bg-red-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'low':
        return 'text-orange-600 bg-orange-100';
      case 'safe':
        return 'text-green-600 bg-green-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskLevelIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'high':
        return <AlertTriangle className="w-5 h-5 text-red-600" />;
      case 'medium':
        return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
      case 'low':
        return <Clock className="w-5 h-5 text-orange-600" />;
      case 'safe':
        return <CheckCircle className="w-5 h-5 text-green-600" />;
      default:
        return <Shield className="w-5 h-5 text-gray-600" />;
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  return (
    <div className="space-y-6">
      {/* En-tête */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Analyse de fichier</h1>
        <p className="text-gray-600">Uploadez un fichier pour l'analyser avec notre système de détection hybride</p>
      </div>

      {/* Zone d'upload */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Sélectionner un fichier</h3>
        
        <div
          className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
            dragActive
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-300 hover:border-gray-400'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          
          <p className="text-lg font-medium text-gray-900 mb-2">
            Glissez-déposez votre fichier ici
          </p>
          <p className="text-sm text-gray-600 mb-4">
            ou cliquez pour sélectionner un fichier
          </p>
          
          <input
            type="file"
            onChange={handleFileSelect}
            className="hidden"
            id="file-upload"
            accept=".exe,.dll,.pdf,.docx,.zip,.rar,.7z"
          />
          <label
            htmlFor="file-upload"
            className="btn-primary cursor-pointer inline-flex items-center space-x-2"
          >
            <File className="w-4 h-4" />
            <span>Sélectionner un fichier</span>
          </label>
        </div>

        {/* Fichier sélectionné */}
        {selectedFile && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <div className="flex items-center space-x-3">
              <File className="w-5 h-5 text-gray-600" />
              <div className="flex-1">
                <p className="text-sm font-medium text-gray-900">{selectedFile.name}</p>
                <p className="text-xs text-gray-500">
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                </p>
              </div>
              <button
                onClick={analyzeFile}
                disabled={isAnalyzing}
                className={`btn-primary flex items-center space-x-2 ${
                  isAnalyzing ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                {isAnalyzing ? (
                  <div className="loading-spinner w-4 h-4"></div>
                ) : (
                  <Shield className="w-4 h-4" />
                )}
                <span>
                  {isAnalyzing ? 'Analyse en cours...' : 'Analyser le fichier'}
                </span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Résultats de l'analyse */}
      {analysisResult && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Résultats de l'analyse</h3>
          
          <div className="space-y-4">
            {/* Statut principal */}
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center space-x-3">
                {getRiskLevelIcon(analysisResult.risk_level)}
                <div>
                  <p className="text-lg font-medium text-gray-900">
                    {analysisResult.is_threat ? 'Menace détectée' : 'Fichier sécurisé'}
                  </p>
                  <p className="text-sm text-gray-600">
                    Niveau de risque: {analysisResult.risk_level.toUpperCase()}
                  </p>
                </div>
              </div>
              <div className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(analysisResult.risk_level)}`}>
                {analysisResult.risk_level.toUpperCase()}
              </div>
            </div>

            {/* Métriques détaillées */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-white border rounded-lg">
                <p className="text-2xl font-bold text-gray-900">
                  {(analysisResult.confidence * 100).toFixed(1)}%
                </p>
                <p className="text-sm text-gray-600">Confiance</p>
              </div>
              <div className="text-center p-4 bg-white border rounded-lg">
                <p className={`text-2xl font-bold ${getConfidenceColor(analysisResult.confidence)}`}>
                  {(analysisResult.final_score * 100).toFixed(1)}%
                </p>
                <p className="text-sm text-gray-600">Score de menace</p>
              </div>
              <div className="text-center p-4 bg-white border rounded-lg">
                <p className="text-2xl font-bold text-gray-900">
                  {analysisResult.analysis_method}
                </p>
                <p className="text-sm text-gray-600">Méthode d'analyse</p>
              </div>
            </div>

            {/* Recommandations */}
            {analysisResult.recommendations.length > 0 && (
              <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h4 className="font-medium text-blue-900 mb-2">Recommandations</h4>
                <ul className="space-y-1">
                  {analysisResult.recommendations.map((recommendation, index) => (
                    <li key={index} className="text-sm text-blue-800 flex items-start space-x-2">
                      <span className="text-blue-600 mt-1">•</span>
                      <span>{recommendation}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Informations techniques */}
            <div className="p-4 bg-gray-50 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-2">Informations techniques</h4>
              <div className="text-sm text-gray-600 space-y-1">
                <p>Méthode d'analyse: {analysisResult.analysis_method}</p>
                <p>Timestamp: {new Date(analysisResult.timestamp).toLocaleString('fr-FR')}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Erreur */}
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

      {/* Conseils de sécurité */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Conseils de sécurité</h3>
        <div className="space-y-3">
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Analysez tous les fichiers suspects</p>
              <p className="text-xs text-gray-600">Notre système hybride détecte les menaces avancées</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Surveillez les recommandations</p>
              <p className="text-xs text-gray-600">Suivez les conseils de sécurité fournis</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Utilisez la quarantaine si nécessaire</p>
              <p className="text-xs text-gray-600">Isolez les fichiers suspects pour analyse</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FileUpload; 