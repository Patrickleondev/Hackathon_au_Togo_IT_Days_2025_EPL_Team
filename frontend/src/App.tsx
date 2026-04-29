import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Threats from './pages/Threats'
import Agents from './pages/Agents'
import Analyze from './pages/Analyze'
import Scans from './pages/Scans'
import Stats from './pages/Stats'
import { getToken } from './api/client'

function Protected({ children }: { children: JSX.Element }) {
  return getToken() ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<Protected><Layout /></Protected>}>
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
