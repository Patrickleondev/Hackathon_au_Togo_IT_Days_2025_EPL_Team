import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, Settings, BarChart3, Upload, Menu, X, Search } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Threats from './components/Threats';
import Scan from './components/Scan';
import Statistics from './components/Statistics';
import SettingsPage from './components/Settings';
import FileUpload from './components/FileUpload';
import NotificationSystem from './components/NotificationSystem';
import RealtimeMonitor from './components/RealtimeMonitor';
import './App.css';

interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
}

function App() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([
    {
      id: '1',
      type: 'success',
      title: 'Scan système terminé',
      message: 'Aucune menace détectée sur votre système',
      timestamp: new Date(Date.now() - 2 * 60 * 1000), // 2 minutes ago
      read: false
    },
    {
      id: '2',
      type: 'info',
      title: 'Mise à jour disponible',
      message: 'Une nouvelle version de RansomGuard AI est disponible',
      timestamp: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
      read: false
    },
    {
      id: '3',
      type: 'warning',
      title: 'Analyse en cours',
      message: 'Analyse de fichier en cours...',
      timestamp: new Date(Date.now() - 10 * 60 * 1000), // 10 minutes ago
      read: true
    }
  ]);

  const toggleMobileMenu = () => {
    setMobileMenuOpen(!mobileMenuOpen);
  };

  const handleMarkAsRead = (id: string) => {
    setNotifications(prev => 
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
  };

  const handleDeleteNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const handleClearAllNotifications = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        {/* Header amélioré */}
        <header className="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              {/* Logo et titre */}
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-10 h-10 bg-gradient-to-br from-blue-600 to-blue-700 rounded-lg shadow-sm">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div className="hidden sm:block">
                  <h1 className="text-xl font-bold text-gray-900">RansomGuard AI</h1>
                  <p className="text-sm text-gray-500">Protection intelligente contre les ransomware</p>
                </div>
                <div className="sm:hidden">
                  <h1 className="text-lg font-bold text-gray-900">RansomGuard</h1>
                </div>
              </div>

              {/* Barre de recherche (desktop) */}
              <div className="hidden md:flex flex-1 max-w-md mx-8">
                <div className="relative w-full">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                  <input
                    type="text"
                    placeholder="Rechercher des fichiers, menaces..."
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Actions du header */}
              <div className="flex items-center space-x-4">
                {/* Indicateur de statut */}
                <div className="hidden sm:flex items-center space-x-2 text-sm text-gray-600">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span>Système protégé</span>
                </div>

                {/* Système de notification amélioré */}
                <NotificationSystem
                  notifications={notifications}
                  onMarkAsRead={handleMarkAsRead}
                  onDelete={handleDeleteNotification}
                  onClearAll={handleClearAllNotifications}
                />

                {/* Badge hackathon */}
                <div className="hidden lg:block">
                  <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white text-xs px-3 py-1 rounded-full font-medium">
                    Hackathon TID 2025
                  </div>
                </div>

                {/* Bouton menu mobile */}
                <button
                  onClick={toggleMobileMenu}
                  className="md:hidden p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors duration-200"
                >
                  {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                </button>
              </div>
            </div>

            {/* Barre de recherche mobile */}
            <div className="md:hidden pb-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                <input
                  type="text"
                  placeholder="Rechercher..."
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>
          </div>
        </header>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col lg:flex-row space-y-8 lg:space-y-0 lg:space-x-8">
            {/* Sidebar responsive */}
            <nav className={`lg:w-64 space-y-2 ${mobileMenuOpen ? 'block' : 'hidden lg:block'}`}>
              <NavLink to="/" icon={<Activity />} label="Tableau de bord" />
              <NavLink to="/upload" icon={<Upload />} label="Analyse de fichier" />
              <NavLink to="/threats" icon={<AlertTriangle />} label="Menaces détectées" />
              <NavLink to="/scan" icon={<Shield />} label="Scanner le système" />
              <NavLink to="/statistics" icon={<BarChart3 />} label="Statistiques" />
              <NavLink to="/monitor" icon={<Activity />} label="Monitoring temps réel" />
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
                <Route path="/monitor" element={<RealtimeMonitor />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </main>
          </div>
        </div>
      </div>
    </Router>
  );
}

// Composant NavLink amélioré
function NavLink({ to, icon, label }: { to: string; icon: React.ReactNode; label: string }) {
  return (
    <Link
      to={to}
      className="flex items-center space-x-3 px-4 py-3 text-gray-700 hover:bg-blue-50 hover:text-blue-700 rounded-lg transition-all duration-200 group"
    >
      <div className="w-5 h-5 group-hover:scale-110 transition-transform duration-200">{icon}</div>
      <span className="font-medium">{label}</span>
    </Link>
  );
}

export default App; 