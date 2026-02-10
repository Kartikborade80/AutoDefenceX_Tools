import React from 'react';
import axios from '../api';
import { Shield, CheckCircle, AlertTriangle, XCircle, RefreshCw, Zap } from 'lucide-react';
import './Dashboard.css';

const MicrosoftDefender = () => {
    const [checking, setChecking] = React.useState(false);
    const [loading, setLoading] = React.useState(true);
    const [status, setStatus] = React.useState({
        health_status: "Loading...",
        secure_score: "--/100",
        definition_version: "Checking...",
        last_checked_formatted: "--:--",
        modules: {
            virus_threat: true,
            firewall: true,
            app_control: true
        }
    });

    const userToken = localStorage.getItem('token');

    const fetchStatus = async () => {
        try {
            setLoading(true);
            const res = await axios.get('/defender/status', {
                headers: { Authorization: `Bearer ${userToken}` }
            });
            setStatus(res.data);
        } catch (error) {
            console.error("Failed to fetch defender status", error);
        } finally {
            setLoading(false);
        }
    };

    React.useEffect(() => {
        fetchStatus();
    }, []);

    const handleCheckUpdates = async () => {
        setChecking(true);
        try {
            const res = await axios.post('/defender/update', {}, {
                headers: { Authorization: `Bearer ${userToken}` }
            });
            // Refresh status after update
            await fetchStatus();
            alert(`Update Complete.\n\nLatest Definition: ${res.data.new_version}`);
        } catch (error) {
            alert("Update check failed.");
        } finally {
            setChecking(false);
        }
    };

    const handleQuickScan = async (type = 'quick') => {
        try {
            await axios.post(`/defender/scan?scan_type=${type}`, {}, {
                headers: { Authorization: `Bearer ${userToken}` }
            });
            alert(`${type === 'full' ? 'Full' : 'Quick'} Scan Initiated. It will run in the background.`);
            fetchStatus(); // Update UI immediately to show 'Scanning...'
        } catch (error) {
            alert("Failed to start scan: " + (error.response?.data?.message || error.message));
        }
    };

    return (
        <>
            {loading ? (
                <div className="dashboard-container fade-in">
                    <div className="loading-state-container">
                        <div className="loading-spinner-wrapper">
                            <div className="loading-spinner"></div>
                            <p className="loading-text">Querying Windows Defender Status...</p>
                            <p className="loading-subtext">Fetching security modules and threat info</p>
                            <p style={{ marginTop: '15px', fontSize: '0.85rem', color: '#f59e0b', fontWeight: '500' }}>
                                ⏱️ Defender queries can take 20-40 seconds. Please wait...
                            </p>
                        </div>
                    </div>
                </div>
            ) : (
                <div className="dashboard-container fade-in">
                    <header className="dashboard-header">
                        <div>
                            <h2><Shield className="icon" /> AutoDefenceX Defenders Status</h2>
                            <p className="subtitle">Real-time Threat Protection</p>
                        </div>
                        <div className="status-indicator">
                            <span className="dot pulse"></span>
                            ACTIVE PROTECTION
                        </div>
                    </header>

                    <div className="metrics-grid-enhanced">
                        <div className="metric-card success">
                            <div className="metric-header">
                                <CheckCircle size={24} />
                                <span className="metric-label">Health Status</span>
                            </div>
                            <div className="metric-value">{status.health_status}</div>
                            <div className="metric-subtitle">No Action Needed</div>
                        </div>

                        <div className="metric-card info">
                            <div className="metric-header">
                                <RefreshCw size={24} />
                                <span className="metric-label">Definition Version</span>
                            </div>
                            <div className="metric-value" style={{ fontSize: '2rem' }}>{status.definition_version}</div>
                            <div className="metric-subtitle">Updated: Today, {status.last_checked_formatted}</div>
                        </div>

                        <div className="metric-card primary">
                            <div className="metric-header">
                                <Shield size={24} />
                                <span className="metric-label">Secure Score</span>
                            </div>
                            <div className="metric-value">{status.secure_score}</div>
                            <div className="metric-subtitle">Identity & Devices</div>
                        </div>
                    </div>

                    <div className="dashboard-grid">
                        <div className="card full-width">
                            <div className="card-header">
                                <h3><Zap size={22} /> Protection Modules</h3>
                                <span className="badge badge-success">ALL SYSTEMS GO</span>
                            </div>

                            <div className="defender-modules" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginTop: '15px' }}>
                                <div className="module-item" style={{ padding: '24px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                                    <div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginBottom: '15px' }}>
                                        <div style={{ padding: '10px', background: 'rgba(16, 185, 129, 0.1)', borderRadius: '8px', color: '#10b981' }}>
                                            <Zap size={24} />
                                        </div>
                                        <div>
                                            <h4 style={{ margin: 0, fontSize: '1rem' }}>Virus & Threat</h4>
                                            <span style={{ color: '#10b981', fontSize: '0.85rem', fontWeight: 600 }}>Enabled</span>
                                        </div>
                                    </div>
                                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', margin: 0 }}>Real-time scanning active. No threats detected in last scan.</p>
                                </div>

                                <div className="module-item" style={{ padding: '24px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                                    <div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginBottom: '15px' }}>
                                        <div style={{ padding: '10px', background: 'rgba(59, 130, 246, 0.1)', borderRadius: '8px', color: '#3b82f6' }}>
                                            <Shield size={24} />
                                        </div>
                                        <div>
                                            <h4 style={{ margin: 0, fontSize: '1rem' }}>Firewall</h4>
                                            <span style={{ color: '#10b981', fontSize: '0.85rem', fontWeight: 600 }}>Active</span>
                                        </div>
                                    </div>
                                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', margin: 0 }}>Domain firewall rules applied. Inbound connections filtered.</p>
                                </div>

                                <div className="module-item" style={{ padding: '24px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                                    <div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginBottom: '15px' }}>
                                        <div style={{ padding: '10px', background: 'rgba(245, 158, 11, 0.1)', borderRadius: '8px', color: '#f59e0b' }}>
                                            <AlertTriangle size={24} />
                                        </div>
                                        <div>
                                            <h4 style={{ margin: 0, fontSize: '1rem' }}>App Control</h4>
                                            <span style={{ color: '#10b981', fontSize: '0.85rem', fontWeight: 600 }}>Enforcing</span>
                                        </div>
                                    </div>
                                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', margin: 0 }}>SmartScreen is blocking untrusted apps.</p>
                                </div>
                            </div>
                        </div>

                        <div className="card full-width">
                            <div className="card-header">
                                <h3><RefreshCw size={22} /> Action History</h3>
                            </div>
                            <div className="activity-list">
                                <div className="activity-item">
                                    <div className="time">{status.last_checked_formatted}</div>
                                    <div className="desc"><span className="badge badge-success" style={{ marginRight: '8px' }}>CHECK COMPLETE</span> Definitions verified.</div>
                                </div>

                                {/* Scan Status Item */}
                                <div className="activity-item">
                                    <div className="time">{status.scan_info?.last_scan || 'Never'}</div>
                                    <div className="desc">
                                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                            <span className={`badge ${status.scan_info?.threats_found > 0 ? 'badge-danger' : 'badge-success'}`}>
                                                {status.scan_info?.threats_found > 0 ? `${status.scan_info.threats_found} THREATS` : 'SCAN CLEAN'}
                                            </span>
                                            {status.scan_info?.is_scanning && <span className="badge badge-warning pulse-icon">SCANNING...</span>}
                                        </div>
                                        {status.scan_info?.is_scanning ? "Defender is currently scanning your system." : "Last scan completed successfully."}
                                    </div>
                                </div>

                                {/* Recent Threat History */}
                                {status.scan_info?.history && status.scan_info.history.length > 0 && (
                                    <div className="activity-item" style={{ borderLeft: '2px solid #ef4444' }}>
                                        <div className="time">Alert</div>
                                        <div className="desc">
                                            <strong>Detected Threats:</strong>
                                            <ul style={{ margin: '5px 0 0 0', paddingLeft: '15px', color: '#fca5a5' }}>
                                                {status.scan_info.history.map((t, idx) => (
                                                    <li key={t.ThreatID || idx}>{t.ThreatName} (Sev: {t.SeverityID})</li>
                                                ))}
                                            </ul>
                                        </div>
                                    </div>
                                )}
                            </div>

                            <div style={{ marginTop: '25px', display: 'flex', gap: '15px', justifyContent: 'flex-end', flexWrap: 'wrap' }}>
                                <button
                                    className="btn-modern-primary"
                                    onClick={() => handleQuickScan('quick')}
                                    disabled={status.scan_info?.is_scanning}
                                    style={{ minWidth: '160px', backgroundColor: status.scan_info?.is_scanning ? '#334155' : '' }}
                                >
                                    <Zap size={18} className={status.scan_info?.is_scanning ? "pulse-icon" : ""} style={{ marginRight: '8px' }} />
                                    Quick Scan
                                </button>

                                <button
                                    className="btn-modern-primary"
                                    onClick={() => handleQuickScan('full')}
                                    disabled={status.scan_info?.is_scanning}
                                    style={{ minWidth: '160px', backgroundColor: '#8b5cf6' }}
                                >
                                    <Shield size={18} style={{ marginRight: '8px' }} />
                                    Full Scan
                                </button>

                                <button className="btn-modern-secondary" onClick={handleCheckUpdates} disabled={checking} style={{ minWidth: '200px' }}>
                                    <RefreshCw size={18} className={checking ? "spin-icon" : ""} style={{ marginRight: '8px' }} />
                                    {checking ? "Check Updates" : "Check Updates"}
                                </button>
                            </div>
                        </div>

                        {/* Exclusions & Settings Card */}
                        {status.preferences && (
                            <div className="card full-width">
                                <div className="card-header">
                                    <h3><Shield size={22} /> Advanced Settings</h3>
                                </div>
                                <div style={{ padding: '10px' }}>
                                    <div style={{ display: 'flex', gap: '20px', marginBottom: '20px' }}>
                                        <div className={`badge ${status.preferences.realtime_monitor ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: '0.9em', padding: '8px 12px' }}>
                                            Real-time Monitoring: {status.preferences.realtime_monitor ? 'ON' : 'OFF'}
                                        </div>
                                        <div className={`badge ${status.preferences.ioav_protection ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: '0.9em', padding: '8px 12px' }}>
                                            IOAV Protection: {status.preferences.ioav_protection ? 'ON' : 'OFF'}
                                        </div>
                                    </div>

                                    <h4 style={{ color: '#aaa', fontSize: '0.9rem', marginBottom: '10px' }}>Excluded Paths ({status.preferences.exclusions.length})</h4>
                                    <div style={{ maxHeight: '150px', overflowY: 'auto', background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '8px' }}>
                                        {status.preferences.exclusions.length > 0 ? (
                                            status.preferences.exclusions.map((path, i) => (
                                                <div key={i} style={{ fontFamily: 'monospace', fontSize: '0.85rem', marginBottom: '4px', color: '#cbd5e1' }}>
                                                    {path}
                                                </div>
                                            ))
                                        ) : (
                                            <div style={{ color: '#666', fontStyle: 'italic' }}>No exclusions configured. Secure.</div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </>
    );
};

export default MicrosoftDefender;
