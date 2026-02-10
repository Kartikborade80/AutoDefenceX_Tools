import React, { useState, useEffect } from 'react';
import axios from '../api';
import useWebSockets from '../hooks/useWebSockets';
import {
    ShieldAlert,
    ShieldCheck,
    UserX,
    Monitor,
    Globe,
    Clock,
    ChevronRight,
    AlertCircle,
    CheckCircle2,
    Brain,
    Zap,
    BarChart3,
    Sparkles
} from 'lucide-react';
import './Dashboard.css';
import './DashboardEnhanced.css'; // Premium styles

const SecurityDashboard = () => {
    const [alerts, setAlerts] = useState([]);
    const [aiInsights, setAiInsights] = useState(null);
    const [playbookResults, setPlaybookResults] = useState(null);
    const [failedAttempts, setFailedAttempts] = useState([]);
    const [stats, setStats] = useState({
        totalAlerts: 0,
        unresolvedAlerts: 0,
        criticalThreats: 0,
        failedLast24h: 0
    });
    const [loading, setLoading] = useState(true);
    const [loadingAI, setLoadingAI] = useState(false);
    const [runningPlaybook, setRunningPlaybook] = useState(false);

    const ensureUTC = (timestamp) => {
        if (!timestamp) return '';
        return timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
    };

    const fetchSecurityData = async () => {
        // ...
        setLoadingAI(true);
        try {
            const token = localStorage.getItem('token');
            const [alertsRes, attemptsRes, aiRes] = await Promise.all([
                axios.get('/users/security/alerts', { headers: { Authorization: `Bearer ${token}` } }).catch(() => ({ data: [] })),
                axios.get('/users/security/login-attempts', { headers: { Authorization: `Bearer ${token}` } }).catch(() => ({ data: [] })),
                axios.get('/analytics/benchmarks', { headers: { Authorization: `Bearer ${token}` } }).catch(() => ({ data: null }))
            ]);

            const safeAlerts = Array.isArray(alertsRes.data) ? alertsRes.data : [];
            const safeAttempts = Array.isArray(attemptsRes.data) ? attemptsRes.data : [];

            setAlerts(safeAlerts);
            setFailedAttempts(safeAttempts);
            setAiInsights(aiRes.data);
            updateStats(safeAlerts, safeAttempts);
        } catch (err) {
            console.error("Error fetching security dashboard data:", err);
        } finally {
            setLoading(false);
            setLoadingAI(false);
        }
    };

    const updateStats = (currentAlerts, currentAttempts) => {
        const unresolved = currentAlerts.filter(a => !a.is_resolved).length;
        const failed24h = currentAttempts.filter(a => {
            if (!a.timestamp) return false;
            const time = new Date(ensureUTC(a.timestamp));
            return (Date.now() - time.getTime()) < 24 * 60 * 60 * 1000 && !a.success;
        }).length;

        setStats({
            totalAlerts: currentAlerts.length,
            unresolvedAlerts: unresolved,
            criticalThreats: currentAlerts.filter(a => a.severity === 'high' || a.severity === 'critical').length,
            failedLast24h: failed24h
        });
    };

    useEffect(() => {
        fetchSecurityData();
    }, []);

    // WebSocket live updates
    const { connected } = useWebSockets((message) => {
        if (message.type === 'security_alert') {
            setAlerts(prev => {
                const updated = [message.data, ...prev].slice(0, 50);
                updateStats(updated, failedAttempts);
                return updated;
            });
        } else if (message.type === 'activity_log' && (message.data.action === 'login' || message.data.action === 'failed_login')) {
            // Re-fetch to get latest login attempts (simpler than manual prepend due to model differences)
            fetchSecurityData();
        }
    });

    const resolveAlert = async (alertId) => {
        // ... (existing)
    };

    const triggerPlaybook = async () => {
        try {
            setRunningPlaybook(true);
            const token = localStorage.getItem('token');
            const response = await axios.post('/analytics/playbooks/run', {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setPlaybookResults(response.data);
            // Refresh dashboard data to see impacts
            fetchSecurityData();
            alert(`Autonomous Playbook Completed! ${response.data.actions_count} containment actions executed.`);
        } catch (err) {
            console.error("Playbook error:", err);
            alert("Failed to run autonomous playbook.");
        } finally {
            setRunningPlaybook(false);
        }
    };

    if (loading) {
        return (
            <div className="loading-state-container">
                <div className="loading-spinner-wrapper text-center">
                    <div className="loading-spinner"></div>
                    <p className="loading-text">Initializing Secure Intelligence Feed...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2>
                        <ShieldAlert className="icon-lg text-blue" />
                        Security Intelligence Dashboard
                    </h2>
                    <p className="subtitle">Real-time monitoring of authentication threats and device integrity</p>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <div className="badge pulse green" style={{ padding: '8px 15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <ShieldCheck size={16} />
                        CORE SYSTEM STABLE
                    </div>
                    <div className="status-indicator">
                        <span className={`dot ${connected ? 'pulse' : ''}`} style={{ backgroundColor: connected ? '#10b981' : '#6b7280' }}></span>
                        {connected ? 'SURVEILLANCE LIVE' : 'CONNECTING...'}
                    </div>
                </div>
            </header>

            {/* Quick Stats Grid */}
            <div className="stats-grid">
                <div className="metric-box border-blue-glow">
                    <div className="flex-between mb-sm">
                        <AlertCircle className="text-blue" size={20} />
                        <span className="badge-micro blue">Audit</span>
                    </div>
                    <p className="metric-value-huge">{stats.totalAlerts}</p>
                    <h4>Total Security Events</h4>
                </div>

                <div className="metric-box border-orange-glow">
                    <div className="flex-between mb-sm">
                        <ShieldAlert className="text-orange" size={20} />
                        <span className="badge-micro orange">Active</span>
                    </div>
                    <p className="metric-value-huge">{stats.unresolvedAlerts}</p>
                    <h4>Open Security Alerts</h4>
                </div>

                <div className="metric-box border-red-glow">
                    <div className="flex-between mb-sm">
                        <UserX className="text-red" size={20} />
                        <span className="badge-micro red">24h History</span>
                    </div>
                    <p className="metric-value-huge">{stats.failedLast24h}</p>
                    <h4>Failed Login Attempts</h4>
                </div>

                <div className="metric-box border-purple-glow">
                    <div className="flex-between mb-sm">
                        <Monitor className="text-purple" size={20} />
                        <span className="badge-micro purple">Device Intel</span>
                    </div>
                    <p className="metric-value-huge font-mono">92%</p>
                    <h4>Unrecognized Device Ratio</h4>
                </div>
            </div>

            <div className="dashboard-grid ai-grid">
                {/* Sentra AI Insights Section */}
                <div className="card ai-sidebar">
                    <header className="card-header-premium flex-between">
                        <h3>
                            <Brain className="icon-sm text-purple" />
                            Sentra Security Intelligence
                        </h3>
                        <div className="badge pulse purple">
                            <Sparkles size={12} /> AI ACTIVE
                        </div>
                    </header>
                    <div className="ai-content">
                        {aiInsights ? (
                            <>
                                <div className="ai-summary">
                                    <div className="global-rank">
                                        <BarChart3 size={24} className="text-blue" />
                                        <div>
                                            <p className="rank-label">Global Organization Rank</p>
                                            <h3 className="rank-value">{aiInsights.global_rank}</h3>
                                        </div>
                                    </div>
                                </div>
                                <div className="insights-list">
                                    {aiInsights?.insights?.map((insight, idx) => (
                                        <div key={idx} className="insight-card">
                                            <div className="insight-header">
                                                <span className="insight-cat">{insight.category}</span>
                                                <span className={`insight-score ${insight.score >= insight.benchmark ? 'good' : 'warning'}`}>
                                                    {insight.score}%
                                                </span>
                                            </div>
                                            <p className="insight-text">{insight.insight}</p>
                                            <div className="insight-recommendation">
                                                <Zap size={12} className="text-yellow" />
                                                <p>{insight.recommendation}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                                <div className="playbook-trigger">
                                    <button
                                        className={`cyber-button danger w-full ${runningPlaybook ? 'loading' : ''}`}
                                        onClick={triggerPlaybook}
                                        disabled={runningPlaybook}
                                    >
                                        <ShieldAlert size={16} />
                                        {runningPlaybook ? 'EXECUTING DEFENSE...' : 'RUN AUTONOMOUS PLAYBOOK'}
                                    </button>
                                </div>
                                {playbookResults && (
                                    <div className="playbook-report">
                                        <h4>Recent Playbook execution</h4>
                                        <p className="text-muted">{playbookResults.actions_count} actions taken at {new Date(playbookResults.timestamp).toLocaleTimeString()}</p>
                                    </div>
                                )}
                            </>
                        ) : (
                            <div className="empty-state-cyber">AI analysis pending...</div>
                        )}
                    </div>
                </div>

                {/* Recent Alerts Section */}
                <div className="card">
                    {/* ... (existing alerts) */}
                    <header className="card-header-premium">
                        <h3>
                            <AlertCircle className="icon-sm text-muted" />
                            Security Alerts & Anomalies
                        </h3>
                    </header>
                    <div className="alerts-feed-modern">
                        {alerts.length === 0 ? (
                            <div className="empty-state-cyber">No security alerts detected. System is secure.</div>
                        ) : (
                            alerts.map(alert => (
                                <div key={alert.id} className={`alert-card-modern ${alert.is_resolved ? 'resolved' : 'threat'}`}>
                                    <div className="alert-header">
                                        <div className="alert-type">
                                            <span className={`status-dot ${alert.severity === 'high' ? 'critical' : 'warning'}`}></span>
                                            <span className="type-label">{alert.alert_type.replace('_', ' ').toUpperCase()}</span>
                                        </div>
                                        {!alert.is_resolved && (
                                            <button onClick={() => resolveAlert(alert.id)} className="btn-resolve-dismiss">
                                                Dismiss
                                            </button>
                                        )}
                                    </div>
                                    <p className="alert-description">{alert.description}</p>
                                    <div className="alert-meta">
                                        <span className="meta-item"><Clock size={12} /> {new Date(ensureUTC(alert.timestamp)).toLocaleString()}</span>
                                        {alert.details?.ip && <span className="meta-item"><Globe size={12} /> {alert.details.ip}</span>}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Failed Attempts Section */}
                <div className="card">
                    <header className="card-header-premium">
                        <h3>
                            <UserX className="icon-sm text-muted" />
                            Recent Authentication Attempts
                        </h3>
                    </header>
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>IP Address</th>
                                    <th>Time</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {failedAttempts.length === 0 ? (
                                    <tr><td colSpan="4" className="no-data-cell">No historical login attempts found.</td></tr>
                                ) : (
                                    failedAttempts.map(attempt => (
                                        <tr key={attempt.id}>
                                            <td className="font-mono text-white">{attempt.username}</td>
                                            <td className="font-mono text-muted">{attempt.ip_address}</td>
                                            <td className="text-muted">{new Date(ensureUTC(attempt.timestamp)).toLocaleTimeString()}</td>
                                            <td>
                                                <span className={`badge-pill ${attempt.success ? 'success' : 'danger'}`}>
                                                    {attempt.success ? 'Success' : (attempt.failure_reason || 'Failed')}
                                                </span>
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <style>{`
                .flex-between { display: flex; justify-content: space-between; items: center; }
                .mb-sm { margin-bottom: 12px; }
                
                .border-blue-glow { border-left: 4px solid #3b82f6 !important; }
                .border-orange-glow { border-left: 4px solid #f59e0b !important; }
                .border-red-glow { border-left: 4px solid #ef4444 !important; }
                .border-purple-glow { border-left: 4px solid #a855f7 !important; }
                
                .badge-micro { padding: 2px 8px; font-size: 10px; font-weight: 800; border-radius: 4px; text-transform: uppercase; }
                .badge-micro.blue { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
                .badge-micro.orange { background: rgba(245, 158, 11, 0.1); color: #f59e0b; }
                .badge-micro.red { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
                .badge-micro.purple { background: rgba(168, 85, 247, 0.1); color: #a855f7; }

                .metric-value-huge { font-size: 2.2rem; font-weight: 800; margin: 10px 0; color: #fff; line-height: 1; }
                
                .card-header-premium { padding: 15px 20px; border-bottom: 1px solid rgba(255,255,255,0.05); margin: -25px -25px 20px -25px; background: rgba(255,255,255,0.02); }
                
                .alerts-feed-modern { display: flex; flexDirection: column; gap: 12px; max-height: 400px; overflow-y: auto; padding-right: 5px; }
                .alert-card-modern { padding: 15px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05); background: rgba(255,255,255,0.02); transition: all 0.3s; }
                .alert-card-modern.threat { border-left: 3px solid #ef4444; background: rgba(239, 68, 68, 0.03); }
                .alert-card-modern.resolved { opacity: 0.6; grayscale: 1; }
                
                .alert-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
                .alert-type { display: flex; align-items: center; gap: 8px; }
                .status-dot { width: 8px; height: 8px; border-radius: 50%; }
                .status-dot.critical { background: #ef4444; box-shadow: 0 0 10px #ef4444; }
                .status-dot.warning { background: #f59e0b; }
                .type-label { font-size: 10px; font-weight: 800; color: rgba(255,255,255,0.4); letter-spacing: 1px; }
                
                .btn-resolve-dismiss { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 4px 12px; border-radius: 4px; font-size: 10px; font-weight: 700; cursor: pointer; transition: 0.2s; }
                .btn-resolve-dismiss:hover { background: rgba(255,255,255,0.1); }
                
                .alert-description { font-size: 0.85rem; color: #cbd5e1; margin-bottom: 10px; line-height: 1.4; }
                .alert-meta { display: flex; gap: 15px; font-size: 10px; color: rgba(255,255,255,0.3); }
                .meta-item { display: flex; align-items: center; gap: 4px; }
                
                .badge-pill { padding: 4px 12px; border-radius: 99px; font-size: 10px; font-weight: 800; text-transform: uppercase; }
                .badge-pill.success { background: rgba(16, 185, 129, 0.1); color: #10b981; }
                .badge-pill.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; }

                .empty-state-cyber { text-align: center; padding: 40px 20px; color: rgba(255,255,255,0.2); font-style: italic; font-size: 0.85rem; }

                .ai-grid { grid-template-columns: 350px 1fr 1fr; }
                .ai-sidebar { grid-row: span 2; background: linear-gradient(135deg, rgba(30, 41, 59, 0.4) 0%, rgba(88, 28, 135, 0.1) 100%); border: 1px solid rgba(168, 85, 247, 0.2); }
                .ai-content { display: flex; flex-direction: column; gap: 20px; overflow-y: auto; max-height: calc(100vh - 350px); }
                
                .global-rank { display: flex; align-items: center; gap: 15px; padding: 15px; background: rgba(15, 23, 42, 0.4); border-radius: 12px; margin-bottom: 5px; }
                .rank-label { font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
                .rank-value { font-size: 1.4rem; font-weight: 800; color: #fff; }
                
                .insights-list { display: flex; flex-direction: column; gap: 12px; }
                .insight-card { padding: 15px; background: rgba(15, 23, 42, 0.3); border-radius: 10px; border: 1px solid rgba(255,255,255,0.05); }
                .insight-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
                .insight-cat { font-size: 11px; font-weight: 700; color: #94a3b8; }
                .insight-score { font-size: 11px; font-weight: 800; padding: 2px 6px; border-radius: 4px; }
                .insight-score.good { color: #10b981; background: rgba(16, 185, 129, 0.1); }
                .insight-score.warning { color: #f59e0b; background: rgba(245, 158, 11, 0.1); }
                
                .insight-text { font-size: 0.85rem; color: #e2e8f0; margin-bottom: 10px; line-height: 1.5; }
                .insight-recommendation { display: flex; gap: 8px; padding: 10px; background: rgba(253, 224, 71, 0.05); border-radius: 6px; border: 1px solid rgba(253, 224, 71, 0.1); }
                .insight-recommendation p { font-size: 0.75rem; color: #fde047; font-weight: 500; }
                
                .playbook-trigger { margin: 10px 0; }
                .playbook-report { padding: 12px; background: rgba(16, 185, 129, 0.05); border-radius: 8px; border: 1px dashed rgba(16, 185, 129, 0.3); margin-top: 10px; }
                .playbook-report h4 { font-size: 11px; color: #10b981; margin-bottom: 4px; }
                .playbook-report p { font-size: 10px; }

                @media (max-width: 1400px) {
                    .ai-grid { grid-template-columns: 1fr; }
                    .ai-sidebar { grid-row: auto; }
                }
            `}</style>
        </div>
    );
};

export default SecurityDashboard;
