import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Activity, ShieldAlert, Clock, MapPin, Globe } from 'lucide-react';
import './Dashboard.css';

const Activities = () => {
    const [activities, setActivities] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchActivities();
    }, []);

    const ensureUTC = (timestamp) => {
        if (!timestamp) return '';
        return timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
    };

    const fetchActivities = async () => {
        try {
            const token = localStorage.getItem('token');
            const user_id = JSON.parse(localStorage.getItem('user_info') || '{}').id;

            // Fetch real activity logs
            const res = await axios.get(`/users/${user_id}/activity`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const sorted = res.data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            setActivities(sorted);
        } catch (err) {
            console.error("Failed to fetch activities", err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><Activity className="icon-lg" /> Activity & Threat Log</h2>
                <div className="header-meta">
                    <span className="badge blue margin-right">MONITORING ACTIVE</span>
                </div>
            </header>

            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                {/* Attack / Threat Simulator for Endpoint View */}
                <div className="card terminal-card" style={{ height: '100%' }}>
                    <div className="card-header" style={{ borderBottom: '1px solid #334155', background: 'rgba(0,0,0,0.2)' }}>
                        <h3><ShieldAlert size={18} className="text-red" /> Live Threat Interception</h3>
                    </div>
                    <div className="terminal-content" style={{ height: '300px' }}>
                        <div className="terminal-line"><span className="text-green">➜</span> System Integrity Check: <span className="text-green">VERIFIED</span></div>
                        <div className="terminal-line"><span className="text-green">➜</span> Firewall Status: <span className="text-green">ACTIVE (Ruleset v24.1)</span></div>
                        <div className="terminal-line"><span className="text-blue">➜</span> Monitoring incoming packets...</div>
                        <div className="terminal-line"><span className="text-muted">➜</span> Analysis: No active threats detected on local interface.</div>
                        <div className="terminal-line blink"><span className="text-yellow">⚠</span> EVENT: Blocked suspicious connection from 192.168.1.105 (Port 445)</div>
                    </div>
                </div>

                {/* Login History */}
                <div className="card" style={{ height: '100%' }}>
                    <div className="card-header">
                        <h3><Clock size={20} /> Recent Login Activity</h3>
                    </div>
                    {loading ? (
                        <div className="loading-state">Loading history...</div>
                    ) : activities.length === 0 ? (
                        <div className="empty-state">No recent activity recorded.</div>
                    ) : (
                        <div className="table-responsive" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                            <table className="table-unified">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Action</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {activities.map(log => (
                                        <tr key={log.id}>
                                            <td>
                                                <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{new Date(ensureUTC(log.timestamp)).toLocaleString()}</span>
                                            </td>
                                            <td>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    {log.action === 'login' ? <Globe size={14} className="text-blue" /> : <Activity size={14} />}
                                                    <span style={{ textTransform: 'uppercase', fontWeight: 'bold', fontSize: '0.85rem' }}>{log.action}</span>
                                                </div>
                                            </td>
                                            <td>
                                                <span className={`badge ${log.action === 'login' ? 'badge-success' : 'badge-user'} ${log.action === 'failed_login' ? 'error-badge' : ''}`}>
                                                    {log.action === 'failed_login' ? 'FAILED' : 'SUCCESS'}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default Activities;
