import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, Settings, BarChart3, Upload } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Threats from './components/Threats';
import Scan from './components/Scan';
import Statistics from './components/Statistics';
import SettingsPage from './components/Settings';
import FileUpload from './components/FileUpload';
import './App.css';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        {/* Header */}
        <header className="bg-white shadow-sm border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-10 h-10 bg-blue-600 rounded-lg">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-gray-900">RansomGuard AI</h1>
                  <p className="text-sm text-gray-500">Protection intelligente contre les ransomware</p>
                </div>
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2 text-sm text-gray-600">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span>Système protégé</span>
                </div>
                <div className="text-sm text-gray-500">
                  Hackathon TID 2025
                </div>
              </div>
            </div>
          </div>
        </header>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex space-x-8">
            {/* Sidebar */}
            <nav className="w-64 space-y-2">
              <NavLink to="/" icon={<Activity />} label="Tableau de bord" />
              <NavLink to="/upload" icon={<Upload />} label="Analyse de fichier" />
              <NavLink to="/threats" icon={<AlertTriangle />} label="Menaces détectées" />
              <NavLink to="/scan" icon={<Shield />} label="Scanner le système" />
              <NavLink to="/statistics" icon={<BarChart3 />} label="Statistiques" />
              <NavLink to="/settings" icon={<Settings />} label="Paramètres" />
            </nav>

            {/* Main content */}
            <main className="flex-1">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/upload" element={<FileUpload />} />
                <Route path="/threats" element={<Threats />} />
                <Route path="/scan" element={<Scan />} />
                <Route path="/statistics" element={<Statistics />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </main>
          </div>
        </div>
      </div>
    </Router>
  );
}

// Composant NavLink personnalisé
function NavLink({ to, icon, label }: { to: string; icon: React.ReactNode; label: string }) {
  return (
    <a
      href={to}
      className="flex items-center space-x-3 px-4 py-3 text-gray-700 hover:bg-blue-50 hover:text-blue-700 rounded-lg transition-colors duration-200"
    >
      <div className="w-5 h-5">{icon}</div>
      <span className="font-medium">{label}</span>
    </a>
  );
}

export default App; 