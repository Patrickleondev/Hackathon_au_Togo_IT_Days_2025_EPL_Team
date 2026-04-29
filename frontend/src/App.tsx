import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import PublicLayout from './components/PublicLayout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import Agents from './pages/Agents'
import Analyze from './pages/Analyze'
import Scans from './pages/Scans'
import Stats from './pages/Stats'
import Home from './pages/public/Home'
import About from './pages/public/About'
import Features from './pages/public/Features'
import Architecture from './pages/public/Architecture'
import Demo from './pages/public/Demo'
import Contact from './pages/public/Contact'
import { getToken } from './api/client'

function Protected({ children }: { children: JSX.Element }) {
  return getToken() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      {/* Public marketing site */}
      <Route element={<PublicLayout />}>
        <Route index element={<Home />} />
        <Route path="about" element={<About />} />
        <Route path="features" element={<Features />} />
        <Route path="architecture" element={<Architecture />} />
        <Route path="demo" element={<Demo />} />
        <Route path="contact" element={<Contact />} />
      </Route>

      {/* Authentication */}
      <Route path="/login" element={<Login />} />

      {/* SOC dashboard (auth-gated) */}
      <Route path="/app" element={<Protected><Layout /></Protected>}>
        <Route index element={<Dashboard />} />
        <Route path="threats" element={<Threats />} />
        <Route path="agents" element={<Agents />} />
        <Route path="analyze" element={<Analyze />} />
        <Route path="scans" element={<Scans />} />
        <Route path="stats" element={<Stats />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
