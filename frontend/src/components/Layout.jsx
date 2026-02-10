import React, { useState, useEffect } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import {
    Shield, LayoutDashboard, Laptop2, FileText, Search, Users, LogOut,
    Activity, TrendingUp, ClipboardCheck, FileBarChart, Sun, Moon, LifeBuoy, Building,
    Calendar, ClipboardList, MessageCircle, ShieldCheck, ShieldAlert, Globe
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import api from '../api';
import CommandBar from './CommandBar';
import './Layout.css';

const Layout = ({ onLogout }) => {
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const { theme, toggleTheme } = useTheme();
    const [sessionDuration, setSessionDuration] = useState('00:00:00');
    const [currentLiveTime, setCurrentLiveTime] = useState('');
    const [loginTime, setLoginTime] = useState(localStorage.getItem('login_time'));

    // Update loginTime when component mounts or when localStorage changes
    useEffect(() => {
        const storedLoginTime = localStorage.getItem('login_time');
        if (storedLoginTime && storedLoginTime !== loginTime) {
            setLoginTime(storedLoginTime);
        }
    }, []);

    useEffect(() => {
        if (!loginTime) return;

        const loginTimestamp = new Date(loginTime).getTime();

        const updateDuration = () => {
            const now = Date.now();
            const elapsed = Math.max(0, Math.floor((now - loginTimestamp) / 1000));
            const hours = Math.floor(elapsed / 3600);
            const minutes = Math.floor((elapsed % 3600) / 60);
            const seconds = elapsed % 60;
            setSessionDuration(`${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`);

            // Update live current time (real-time clock)
            const currentTime = new Date();
            const formattedTime = currentTime.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
            });
            const formattedDate = currentTime.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
            setCurrentLiveTime(`${formattedDate} ${formattedTime}`);
        };

        updateDuration();
        const interval = setInterval(updateDuration, 1000);
        return () => clearInterval(interval);
    }, [loginTime]);


    // Activity Tracking and Auto-Logout
    useEffect(() => {
        let heartbeatInterval;
        let inactivityTimer;
        let warningTimer;
        const HEARTBEAT_INTERVAL = 60000; // 1 minute
        const INACTIVITY_WARNING = 28 * 60 * 1000; // 28 minutes
        const INACTIVITY_LOGOUT = 30 * 60 * 1000; // 30 minutes

        const sendHeartbeat = async () => {
            try {
                await api.post('/attendance/heartbeat');
            } catch (error) {
                if (error.response?.status === 401) {
                    // Session expired or invalid
                    handleAutoLogout('session_expired');
                }
            }
        };

        const handleAutoLogout = (reason) => {
            const messages = {
                'inactivity': 'You have been logged out due to inactivity.',
                'session_expired': 'Your session has expired. Please login again.',
                'session_invalid': 'You have been logged in from another device. This session has been terminated.'
            };

            // Clear timers
            clearInterval(heartbeatInterval);
            clearTimeout(inactivityTimer);
            clearTimeout(warningTimer);

            // Show message and logout
            alert(messages[reason] || 'You have been logged out.');
            onLogout();
        };

        const showInactivityWarning = () => {
            const continueSession = window.confirm(
                'You will be logged out in 2 minutes due to inactivity. Click OK to continue your session.'
            );

            if (continueSession) {
                // Reset inactivity timer
                resetInactivityTimer();
            } else {
                // Logout immediately
                handleAutoLogout('inactivity');
            }
        };

        const resetInactivityTimer = () => {
            clearTimeout(inactivityTimer);
            clearTimeout(warningTimer);

            // Set warning timer (28 minutes)
            warningTimer = setTimeout(() => {
                showInactivityWarning();
            }, INACTIVITY_WARNING);

            // Set logout timer (30 minutes)
            inactivityTimer = setTimeout(() => {
                handleAutoLogout('inactivity');
            }, INACTIVITY_LOGOUT);
        };

        // Track user activity
        const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart'];
        activityEvents.forEach(event => {
            window.addEventListener(event, resetInactivityTimer);
        });

        // Start heartbeat
        heartbeatInterval = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);

        // Initial heartbeat
        sendHeartbeat();

        // Start inactivity timer
        resetInactivityTimer();

        return () => {
            clearInterval(heartbeatInterval);
            clearTimeout(inactivityTimer);
            clearTimeout(warningTimer);
            activityEvents.forEach(event => {
                window.removeEventListener(event, resetInactivityTimer);
            });
        };
    }, [onLogout]);


    const getRoleLabel = (role) => {
        if (role === 'admin') return 'Admin Session';
        return 'Endpoint Agent';
    };

    const isPersonalTheme = userInfo.role !== 'admin';

    return (
        <div className={`layout ${isPersonalTheme ? 'theme-personal' : ''}`}>
            <CommandBar />
            {/* Sidebar */}
            <nav className="sidebar">
                <div className="sidebar-header">
                    <Shield size={32} color="#007bff" />
                    <h1>AutoDefenceX</h1>
                </div>
                <div className="nav-links">
                    <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <div className="sidebar-icon icon-dashboard"><LayoutDashboard size={22} /></div>
                        <span>Dashboard</span>
                    </NavLink>

                    {/* Admin Only Navigation */}
                    {userInfo.role === 'admin' && (
                        <>
                            <NavLink to="/endpoints" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-endpoints"><Laptop2 size={22} /></div>
                                <span>Endpoints</span>
                            </NavLink>
                            <NavLink to="/users" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-users"><Users size={22} /></div>
                                <span>User Management</span>
                            </NavLink>
                            <NavLink to="/departments" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-departments"><Building size={22} /></div>
                                <span>Departments</span>
                            </NavLink>
                            <NavLink to="/policies" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-policies"><ShieldCheck size={22} /></div>
                                <span>Policies</span>
                            </NavLink>
                            <NavLink to="/forensics" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-forensics"><Search size={22} /></div>
                                <span>Forensics</span>
                            </NavLink>
                            <NavLink to="/reports" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-reports"><FileBarChart size={22} /></div>
                                <span>Reports</span>
                            </NavLink>
                            <NavLink to="/tickets" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-tickets">🎫</div>
                                <span>Support Tickets</span>
                            </NavLink>
                            <NavLink to="/messages" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-messages"><MessageCircle size={22} /></div>
                                <span>Message System</span>
                            </NavLink>
                            <NavLink to="/monitoring" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-monitoring"><Search size={22} /></div>
                                <span>Monitoring</span>
                            </NavLink>
                            <NavLink to="/security" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-forensics"><ShieldAlert size={22} className="text-red-400" /></div>
                                <span className="text-red-200">Security Intel</span>
                            </NavLink>

                            <div className="tab-group-title">Advanced</div>
                            <NavLink to="/healing" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-healing"><Activity size={22} /></div>
                                <span>Network Healing</span>
                            </NavLink>
                            <NavLink to="/predictive" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-predictive"><TrendingUp size={22} /></div>
                                <span>Predictive Threat</span>
                            </NavLink>
                            <NavLink to="/compliance" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-compliance"><ClipboardCheck size={22} /></div>
                                <span>Compliance</span>
                            </NavLink>
                            <NavLink to="/network-scanning" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-endpoints"><Search size={22} /></div>
                                <span>Network Discovery</span>
                            </NavLink>
                            <NavLink to="/topology" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-endpoints"><Globe size={22} className="text-blue-400" /></div>
                                <span className="text-blue-200">Network Topology</span>
                            </NavLink>
                        </>
                    )}

                    {/* HOD Specific Navigation (Monitoring) */}
                    {userInfo.is_department_head && (
                        <NavLink to="/monitoring" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                            <div className="sidebar-icon icon-monitoring"><Search size={22} /></div>
                            <span>Monitoring</span>
                        </NavLink>
                    )}

                    {/* Personal / Endpoint User Navigation - For all non-admins */}
                    {userInfo.role !== 'admin' && (
                        <>
                            <NavLink to="/activities" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-healing"><Activity size={22} /></div>
                                <span>Activities / Attack</span>
                            </NavLink>
                            <NavLink to="/defender" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-dashboard"><Shield size={22} /></div>
                                <span>AutoDefenceX Defenders</span>
                            </NavLink>



                            <NavLink to="/system-info" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-endpoints"><Laptop2 size={22} /></div>
                                <span>System Information</span>
                            </NavLink>

                            <NavLink to="/policies" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-policies"><FileText size={22} /></div>
                                <span>My Policies</span>
                            </NavLink>
                            <NavLink to="/tickets" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-tickets">🎫</div>
                                <span>Support Tickets</span>
                            </NavLink>
                            <NavLink to="/attendance" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-attendance"><Calendar size={22} /></div>
                                <span>My Attendance</span>
                            </NavLink>
                            <NavLink to="/tasks" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-tasks"><ClipboardList size={22} /></div>
                                <span>{userInfo.is_department_head ? "Task Management" : "My Tasks"}</span>
                            </NavLink>
                            <NavLink to="/messages" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                                <div className="sidebar-icon icon-messages"><MessageCircle size={22} /></div>
                                <span>Message System</span>
                            </NavLink>
                        </>
                    )}

                    <div className="tab-group-title">Settings</div>
                    <NavLink to="/about" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <div className="sidebar-icon icon-users">👤</div>
                        <span>Profile & About</span>
                    </NavLink>
                    <NavLink to="/help" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                        <div className="sidebar-icon icon-compliance"><LifeBuoy size={22} /></div>
                        <span>Help & Support</span>
                    </NavLink>
                </div>
            </nav>

            {/* Main Content */}
            <main className="main-content">
                <header className="main-header">
                    <div className="user-access-info">
                        <span className={`role-badge ${userInfo.role}`}>
                            {getRoleLabel(userInfo.role)}
                        </span>
                        <span className="user-name">{userInfo.full_name || userInfo.username}</span>
                        {userInfo.company_name && (
                            <span className="company-tag">| {userInfo.company_name}</span>
                        )}
                    </div>
                    <div className="header-right">
                        <button
                            className="theme-toggle-btn"
                            title="Global Search (Ctrl+K)"
                            onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { ctrlKey: true, key: 'k' }))}
                        >
                            <Search size={18} />
                        </button>
                        <button onClick={toggleTheme} className="theme-toggle-btn" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}>
                            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
                        </button>
                        <div className="login-status">
                            <span className="time-label">Session:</span>
                            <span className="time-value live-timer">{sessionDuration}</span>
                            <span className="time-label" style={{ marginLeft: '16px' }}>Time:</span>
                            <span className="time-value live-timer">{currentLiveTime}</span>
                        </div>
                        <button onClick={onLogout} className="logout-btn-header">
                            <LogOut size={18} />
                            <span>Log Out</span>
                        </button>
                    </div>
                </header>
                <div className="content-wrapper">
                    <Outlet />
                </div>
            </main>
        </div >
    );
};

export default Layout;
