import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import api from './api';
import Login from './components/Login';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import EndpointList from './components/EndpointList';
import UserManagement from './components/UserManagement';
import Policies from './components/Policies';
import Reports from './components/Reports';
import Forensics from './components/Forensics';
import AdminRegister from './components/AdminRegister';
import Departments from './components/Departments';
import NetworkHealing from './components/NetworkHealing';
import PredictiveThreats from './components/PredictiveThreats';
import Compliance from './components/Compliance';
import About from './components/About';
import TicketSystem from './components/TicketSystem';
import Monitoring from './components/Monitoring'; // Added Monitoring import
import PCInfo from './components/PCInfo';
import Help from './components/Help';
import Activities from './components/Activities';
import MicrosoftDefender from './components/MicrosoftDefender';
import ChatbotWidget from './components/ChatbotWidget';
import DepartmentHeadView from './components/DepartmentHeadView';
import Attendance from './components/Attendance';
import Tasks from './components/Tasks';
import Messaging from './components/Messaging';
import SystemInfo from './components/SystemInfo';
import SecurityDashboard from './components/SecurityDashboard';
import NetworkScanner from './components/NetworkScanner';
import EndpointDetail from './components/EndpointDetail';
import NetworkTopology from './components/NetworkTopology';
import UserActivityHandler from './components/UserActivityHandler';
import { ThemeProvider } from './context/ThemeContext';
import './GlobalStyles.css';
import './App.css';
import './components/ModernUI.css';
import './components/ModernButtons.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [userRole, setUserRole] = useState(localStorage.getItem('role') || null);
  const [loginKey, setLoginKey] = useState(Date.now()); // Force re-mount on login

  useEffect(() => {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    if (token) {
      setIsAuthenticated(true);
      setUserRole(role);
    }
  }, []);

  const handleLogin = (role) => {
    setIsAuthenticated(true);
    setUserRole(role);
    localStorage.setItem('role', role);
    setLoginKey(Date.now()); // Update key to force Layout re-mount
  };

  const handleLogout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (err) {
      console.error("Logout API call failed", err);
    }
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    localStorage.removeItem('user_info');
    localStorage.removeItem('login_time');
    setIsAuthenticated(false);
    setUserRole(null);
  };

  return (
    <ThemeProvider>
      <Router>
        <Routes>
          <Route path="/login" element={!isAuthenticated ? <Login onLogin={handleLogin} /> : <Navigate to="/" />} />
          <Route path="/register-admin" element={<AdminRegister />} />

          <Route path="/" element={isAuthenticated ? <Layout key={loginKey} onLogout={handleLogout} /> : <Navigate to="/login" />}>
            <Route index element={<Dashboard role={userRole} />} />
            <Route path="endpoints" element={<EndpointList />} />
            <Route path="endpoints/:id" element={<EndpointDetail />} />
            <Route path="users" element={<UserManagement />} />
            <Route path="departments" element={<Departments />} />
            <Route path="policies" element={<Policies />} />
            <Route path="reports" element={<Reports />} />
            <Route path="forensics" element={<Forensics />} />
            <Route path="healing" element={<NetworkHealing />} />
            <Route path="predictive" element={<PredictiveThreats />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="about" element={<About />} />
            <Route path="tickets" element={<TicketSystem />} />
            <Route path="pc-info" element={<PCInfo />} />
            <Route path="help" element={<Help />} />
            <Route path="activities" element={<Activities />} />
            <Route path="defender" element={<MicrosoftDefender />} />
            <Route path="department-head" element={<DepartmentHeadView />} />
            <Route path="monitoring" element={<Monitoring />} />
            <Route path="attendance" element={<Attendance />} />
            <Route path="tasks" element={<Tasks />} />
            <Route path="messages" element={<Messaging />} />
            <Route path="system-info" element={<SystemInfo />} />
            <Route path="security" element={<SecurityDashboard />} />
            <Route path="network-scanning" element={<NetworkScanner />} />
            <Route path="topology" element={<NetworkTopology />} />
          </Route>
        </Routes>

        {/* AI Chatbot - Available on all pages */}
        <ChatbotWidget />

        {/* Activity Tracking for Auto-Logout */}
        <UserActivityHandler
          isAuthenticated={isAuthenticated}
          onLogout={handleLogout}
        />
      </Router>
    </ThemeProvider>
  );
}

export default App;
