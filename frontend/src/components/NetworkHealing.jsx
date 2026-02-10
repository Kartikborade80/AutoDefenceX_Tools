import React, { useState, useEffect } from 'react';
import { Network, ShieldAlert, Activity, ShieldCheck, ShieldOff, AlertTriangle, Monitor, Power, Lock, Unlock } from 'lucide-react';
import axios from '../api';
import './Dashboard.css';

const NetworkHealing = () => {
    const [endpoints, setEndpoints] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchEndpoints();
    }, []);

    const fetchEndpoints = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/endpoints/', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setEndpoints(res.data);
        } catch (err) {
            console.error("Failed to fetch endpoints", err);
        } finally {
            setLoading(false);
        }
    };

    const handleIsolate = async (id, hostname) => {
        if (!window.confirm(`Are you sure you want to ISOLATE ${hostname}? This will disconnect it from all network resources except the security console.`)) return;
        try {
            const token = localStorage.getItem('token');
            await axios.post(`/endpoints/${id}/isolate`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchEndpoints();
            alert(`${hostname} quarantined.`);
        } catch (err) {
            alert("Isolation failed.");
        }
    };

    const handleRestore = async (id, hostname) => {
        try {
            const token = localStorage.getItem('token');
            await axios.post(`/endpoints/${id}/restore`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchEndpoints();
            alert(`${hostname} restored to network.`);
        } catch (err) {
            alert("Restoration failed.");
        }
    };

    const isolatedCount = endpoints.filter(e => e.status === 'isolated').length;

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2><Network className="icon-lg text-blue" /> Network Healing</h2>
                    <p className="subtitle">Asset Containment & Automated Recovery</p>
                </div>
                <div className="header-meta">
                    <span className={`badge ${isolatedCount > 0 ? 'red pulse' : 'green'}`}>
                        {isolatedCount} ISOLATED ASSETS
                    </span>
                </div>
            </header>

            <div className="card full-width error-highlight">
                <div style={{ display: 'flex', gap: '15px', alignItems: 'flex-start' }}>
                    <ShieldAlert size={32} className="text-red" />
                    <div>
                        <h3>Containment & Segmentation Center</h3>
                        <p>
                            Control lateral movement by isolating compromised endpoints. Isolated machines lose all connectivity except to this command center.
                        </p>
                    </div>
                </div>
            </div>

            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr' }}>
                <div className="card">
                    <div className="card-header">
                        <h3><Monitor size={18} /> Managed Endpoints Status</h3>
                        {loading && <span className="subtitle">Syncing...</span>}
                    </div>

                    <div className="table-unified-wrapper" style={{ marginTop: '15px' }}>
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Hostname</th>
                                    <th>User</th>
                                    <th>Department</th>
                                    <th>Security Status</th>
                                    <th className="text-right">Containment Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {endpoints.length === 0 ? (
                                    <tr><td colSpan="5" className="text-center">No active endpoints found.</td></tr>
                                ) : (
                                    endpoints.map(e => (
                                        <tr key={e.endpoint_id}>
                                            <td className="mono">{e.hostname}</td>
                                            <td>{e.full_name}</td>
                                            <td><span className="badge-micro blue">{e.department_name}</span></td>
                                            <td>
                                                {e.status === 'isolated' ? (
                                                    <span className="badge red pulse"><ShieldOff size={12} /> QUARANTINED</span>
                                                ) : (
                                                    <span className="badge green"><ShieldCheck size={12} /> PROTECTED</span>
                                                )}
                                            </td>
                                            <td className="text-right">
                                                {e.status === 'isolated' ? (
                                                    <button
                                                        className="btn-modern-primary btn-modern-sm"
                                                        onClick={() => handleRestore(e.endpoint_id, e.hostname)}
                                                        style={{ background: 'var(--success-green)' }}
                                                    >
                                                        <Unlock size={14} /> RESTORE
                                                    </button>
                                                ) : (
                                                    <button
                                                        className="btn-modern-danger btn-modern-sm"
                                                        onClick={() => handleIsolate(e.endpoint_id, e.hostname)}
                                                    >
                                                        <Lock size={14} /> ISOLATE
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div className="stats-grid">
                <div className="metric-box border-red-glow">
                    <h4>Quarantined Assets</h4>
                    <p className="metric-value">{isolatedCount}</p>
                </div>
                <div className="metric-box border-green-glow">
                    <h4>Auto-Healed Events (24h)</h4>
                    <p className="metric-value">12</p>
                </div>
                <div className="metric-box border-blue-glow">
                    <h4>Rollback Points</h4>
                    <p className="metric-value">42</p>
                </div>
            </div>
        </div>
    );
};

export default NetworkHealing;
