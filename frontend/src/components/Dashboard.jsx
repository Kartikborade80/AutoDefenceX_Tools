import React, { useState, useEffect } from 'react';
import axios from '../api';
import {
    Shield,
    Activity,
    Terminal,
    AlertTriangle,
    CheckCircle,
    Clock,
    Zap,
    Lock,
    Search,
    Cpu,
    Database
} from 'lucide-react';
import ScanningPopup from './ScanningPopup';
import useWebSockets from '../hooks/useWebSockets';
import './Dashboard.css';
import './DashboardEnhanced.css';
import IncidentReporting from './IncidentReporting';
import TrustScore from './TrustScore';
import PasswordChangeModal from './PasswordChangeModal';

const useLiveData = (fetcher, interval = 5000) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const update = async () => {
            try {
                const result = await fetcher();
                setData(result);
            } finally {
                setLoading(false);
            }
        };
        update();
        const id = setInterval(update, interval);
        return () => clearInterval(id);
    }, [interval]);

    return { data, loading };
};

const Dashboard = () => {
    const [userInfo, setUserInfo] = useState({});
    const [stats, setStats] = useState({ totalEndpoints: 0, agentsOnline: 0, totalUsers: 0 });
    const [lastScanTime, setLastScanTime] = useState(null);
    const [role, setRole] = useState('');
    const [showScanPopup, setShowScanPopup] = useState(false);
    const [currentScanId, setCurrentScanId] = useState(null);
    const [liveActivities, setLiveActivities] = useState([
        { time: 'System', desc: 'Real-time monitoring active.' }
    ]);
    const [showPasswordChange, setShowPasswordChange] = useState(false);

    useEffect(() => {
        const storedInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
        setUserInfo(storedInfo);
        setRole(localStorage.getItem('role') || 'user');

        // Check if password change is required
        if (storedInfo.must_change_password) {
            setShowPasswordChange(true);
        }
    }, []);

    const { data: liveStats } = useLiveData(async () => {
        const token = localStorage.getItem('token');
        const orgId = userInfo.organization_id || 1; // Default to 1 if not set
        const [endpointsRes, usersRes, scanRes, messagesRes] = await Promise.all([
            axios.get('/endpoints/', { headers: { Authorization: `Bearer ${token}` } }),
            axios.get('/users/', { headers: { Authorization: `Bearer ${token}` } }),
            axios.get('/scans/last', { headers: { Authorization: `Bearer ${token}` } }),
            axios.get(`/messages/community/${orgId}`, { headers: { Authorization: `Bearer ${token}` } }).catch(() => ({ data: [] }))
        ]);

        if (scanRes.data.timestamp) {
            setLastScanTime(new Date(scanRes.data.timestamp).toLocaleString());
        }

        return {
            totalEndpoints: endpointsRes.data.length,
            agentsOnline: endpointsRes.data.filter(e => e.status === 'online').length,
            totalUsers: usersRes.data.length,
            riskScore: endpointsRes.data.reduce((acc, ep) => acc + (ep.trust_score < 50 ? 1 : 0), 0),
            recentMessages: messagesRes.data ? messagesRes.data.slice(0, 3) : []  // Top 3 recent
        };
    }, 5000);

    const handleForceScan = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.post('/scans/trigger-live', {}, { headers: { Authorization: `Bearer ${token}` } });
            setCurrentScanId(res.data.id);
            setShowScanPopup(true);
        } catch (err) {
            alert("Failed to initiate scan: " + (err.response?.data?.detail || err.message));
        }
    };

    useEffect(() => {
        if (liveStats) setStats(liveStats);
    }, [liveStats]);

    const { connected } = useWebSockets((message) => {
        if (message.type === 'activity_log') {
            const newActivity = {
                time: new Date(message.data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                desc: <span><strong>{message.data.username}</strong>: {message.data.action.replace('_', ' ')}</span>
            };
            setLiveActivities(prev => [newActivity, ...prev].slice(0, 10));
        }
    });

    // Unified Dashboard for Endpoint Users (Non-Admins)
    if (role !== 'admin') {
        return (
            <div className="dashboard-container fade-in">
                <PasswordChangeModal
                    isOpen={showPasswordChange}
                    onClose={() => setShowPasswordChange(false)}
                    isForced={true}
                    userInfo={userInfo}
                />
                <ScanningPopup
                    isOpen={showScanPopup}
                    onClose={() => setShowScanPopup(false)}
                    scanId={currentScanId}
                    token={localStorage.getItem('token')}
                />

                <header className="dashboard-header">
                    <div>
                        <h2><Shield className="icon" /> Enterprise Endpoint Overview</h2>
                        <p className="subtitle">Welcome back, {userInfo.full_name || userInfo.username} | {userInfo.company_name || 'Tech Mahindra'}</p>
                    </div>
                    <div className="running-indicator">
                        <span className="dot pulse"></span>
                        PROTECTED
                    </div>
                </header>

                <div className="dashboard-grid personal-grid-modern">
                    {/* 1. Attendance Widget */}
                    <div className="card scan-card">
                        <div className="card-header-icon">
                            <Clock size={24} className="text-primary" />
                            <h3>My Attendance</h3>
                        </div>
                        <p className="text-alignment-fix">Daily work status tracking.</p>
                        <div className="highlight-system-box">
                            <strong>Status:</strong> {new Date().getHours() > 9 ? 'Present' : 'Not Clocked In'}
                            <br />
                            <span style={{ fontSize: '0.85em', opacity: 0.8 }}>Shift: 9:00 AM - 6:00 PM</span>
                        </div>
                        <div style={{ marginTop: 'auto' }}>
                            <p className="scan-meta-text">
                                <CheckCircle size={12} style={{ color: '#10b981' }} /> Compliance Verified
                            </p>
                        </div>
                    </div>

                    {/* 2. Compliance & Health */}
                    <div className="card stat-card-wide">
                        <h3><Shield size={22} /> Endpoint Compliance</h3>
                        <div className="health-metrics">
                            <div className="health-bar-container">
                                <span>Policy Adherence</span>
                                <div className="health-bar"><div className="fill green" style={{ width: '100%' }}></div></div>
                            </div>
                            <div className="health-bar-container">
                                <span>Agent Health</span>
                                <div className="health-bar"><div className="fill blue" style={{ width: '100%' }}></div></div>
                            </div>
                        </div>
                        <div className="compliance-badges" style={{ display: 'flex', gap: '10px', marginTop: '15px' }}>
                            <span className="badge badge-success">AV Active</span>
                            <span className="badge badge-success">DLP On</span>
                            <span className="badge badge-success">Firewall Up</span>
                        </div>
                    </div>

                    {/* 3. Task Summary */}
                    <div className="card info-card">
                        <h3><Activity size={22} /> Pending Tasks</h3>
                        <div className="vault-list">
                            <div className="vault-item">
                                <AlertTriangle size={14} className="text-yellow" />
                                <span>System Update Pending</span>
                            </div>
                            <div className="vault-item">
                                <CheckCircle size={14} className="text-blue" />
                                <span>Weekly Report Submitted</span>
                            </div>
                            <div className="vault-item">
                                <Zap size={14} className="text-primary" />
                                <span>Security Training Due</span>
                            </div>
                        </div>
                    </div>

                    {/* 4. Messages / Announcements - Real Data */}
                    <div className="card full-width activity-history-expanded">
                        <div className="card-header">
                            <h3><Database size={22} /> Recent Messages</h3>
                            <span className="badge">HR & IT ALERTS</span>
                        </div>
                        <div className="table-responsive">
                            <table className="table-unified">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Sender</th>
                                        <th>Content</th>
                                        <th>Type</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {/* We need to fetch messages. Since useLiveData is generic, let's add messages to it or fetch inside Dashboard */}
                                    {liveStats && liveStats.recentMessages && liveStats.recentMessages.length > 0 ? (
                                        liveStats.recentMessages.map(msg => (
                                            <tr key={msg.id}>
                                                <td className="mono">{new Date(msg.timestamp).toLocaleDateString()}</td>
                                                <td>{msg.sender_name || 'System'}</td>
                                                <td style={{ maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                    {msg.content}
                                                </td>
                                                <td>
                                                    <span className={`badge ${msg.message_type === 'community' ? 'badge-info' : 'badge-warning'}`}>
                                                        {msg.message_type}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))
                                    ) : (
                                        <tr>
                                            <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                                                No recent messages found.
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="dashboard-container fade-in">
            <PasswordChangeModal
                isOpen={showPasswordChange}
                onClose={() => setShowPasswordChange(false)}
                isForced={true}
                userInfo={userInfo}
            />
            <ScanningPopup
                isOpen={showScanPopup}
                onClose={() => setShowScanPopup(false)}
                scanId={currentScanId}
                token={localStorage.getItem('token')}
            />

            <header className="page-header">
                <div>
                    <h2><Shield className="icon" /> Enterprise Command Center</h2>
                    <p className="subtitle">Real-time surveillance & endpoint intelligence</p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: '15px' }}>
                    <button className="btn-modern-primary btn-modern-sm" onClick={handleForceScan}>
                        <Zap size={14} /> ALL SCAN
                    </button>
                    <div className="status-indicator">
                        <span className={`dot ${connected ? 'pulse' : ''}`} style={{ backgroundColor: connected ? '#10b981' : '#6b7280' }}></span>
                        {connected ? 'SURVEILLANCE LIVE' : 'CONNECTING...'}
                    </div>
                </div>
            </header>

            {role === 'admin' ? (
                <>
                    {/* Enhanced Metrics Grid - Admin Only */}
                    <div className="metrics-grid-enhanced">
                        <div className="metric-card primary">
                            <div className="metric-header">
                                <Terminal size={24} />
                                <span className="metric-label">Total Endpoints</span>
                            </div>
                            <div className="metric-value">{stats.totalEndpoints}</div>
                            <div className="metric-subtitle">Protected Devices</div>
                        </div>

                        <div className="metric-card success">
                            <div className="metric-header">
                                <Zap size={24} />
                                <span className="metric-label">Online</span>
                            </div>
                            <div className="metric-value">{stats.agentsOnline}</div>
                            <div className="metric-subtitle">Active Agents</div>
                        </div>

                        <div className="metric-card warning">
                            <div className="metric-header">
                                <AlertTriangle size={24} />
                                <span className="metric-label">Offline</span>
                            </div>
                            <div className="metric-value">{stats.totalEndpoints - stats.agentsOnline}</div>
                            <div className="metric-subtitle">Inactive Devices</div>
                        </div>

                        <div className="metric-card info">
                            <div className="metric-header">
                                <Database size={24} />
                                <span className="metric-label">Active Sessions</span>
                            </div>
                            <div className="metric-value">{stats.totalUsers}</div>
                            <div className="metric-subtitle">Current Users</div>
                        </div>
                    </div>

                    {/* Security Overview Cards - Admin Only */}
                    <div className="dashboard-grid">
                        <div className="card security-overview">
                            <div className="card-header">
                                <h3><Shield size={22} /> Security Posture</h3>
                                <span className="badge badge-success">Healthy</span>
                            </div>
                            <div className="security-metrics">
                                <div className="security-item">
                                    <div className="security-label">
                                        <CheckCircle size={16} className="text-success" />
                                        <span>Risk Level Score</span>
                                    </div>
                                    <span className="security-value text-red">{stats.riskScore || 0}</span>
                                </div>
                                <div className="security-item">
                                    <div className="security-label">
                                        <Shield size={16} className="text-primary" />
                                        <span>Protected Endpoints</span>
                                    </div>
                                    <span className="security-value">{stats.totalEndpoints}</span>
                                </div>
                                <div className="security-item">
                                    <div className="security-label">
                                        <AlertTriangle size={16} className="text-warning" />
                                        <span>Quarantined Assets</span>
                                    </div>
                                    <span className="security-value">0</span>
                                </div>
                                <div className="security-item">
                                    <div className="security-label">
                                        <Activity size={16} className="text-info" />
                                        <span>Network Health</span>
                                    </div>
                                    <span className="security-value">98.5%</span>
                                </div>
                            </div>
                        </div>

                        <div className="card activity-card">
                            <div className="card-header">
                                <h3><Activity size={22} /> Live Intelligence Feed</h3>
                                <span className="badge">REAL-TIME</span>
                            </div>
                            <div className="activity-list">
                                {liveActivities.map((activity, idx) => (
                                    <div key={idx} className="activity-item">
                                        <div className="time">{activity.time}</div>
                                        <div className="desc">{activity.desc}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="card monitoring-card">
                            <h3><Search size={22} /> Active Surveillance</h3>
                            <div className="monitoring-stats">
                                <div className="mon-item">
                                    <span>Process Watch</span>
                                    <span className="text-success">STABLE</span>
                                </div>
                                <div className="mon-item">
                                    <span>Network Traffic</span>
                                    <span className="text-info">NOMINAL</span>
                                </div>
                                <div className="mon-item">
                                    <span>Threat Level</span>
                                    <span className="text-success">LOW</span>
                                </div>
                                <div className="mon-item">
                                    <span>Compliance Status</span>
                                    <span className="text-success">COMPLIANT</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </>
            ) : (
                <div className="dashboard-grid user-dashboard">
                    <TrustScore />
                    <IncidentReporting />

                    <div className="card monitoring-card">
                        <h3><Shield size={22} /> System Status</h3>
                        <div className="monitoring-stats">
                            <div className="mon-item">
                                <span>Protection</span>
                                <span className="text-success">ACTIVE</span>
                            </div>
                            <div className="mon-item">
                                <span>Policy</span>
                                <span className="text-success">ENFORCED</span>
                            </div>
                            <div className="mon-item">
                                <span>Updates</span>
                                <span className="text-info">CHECKING...</span>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Dashboard;
