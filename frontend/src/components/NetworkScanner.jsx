import React, { useState, useEffect, useRef } from 'react';
import axios from '../api';
import { Activity, Shield, Terminal, Search, CheckCircle, AlertCircle, RefreshCw, Smartphone, Monitor } from 'lucide-react';
import './Dashboard.css';

const NetworkScanner = () => {
    const [isScanning, setIsScanning] = useState(false);
    const [scanResults, setScanResults] = useState(null);
    const [error, setError] = useState(null);
    const terminalRef = useRef(null);

    const runDiscovery = async () => {
        setIsScanning(true);
        setError(null);
        setScanResults(null);
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/scans/network-discovery', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setScanResults(res.data);
        } catch (err) {
            console.error(err);
            setError(err.response?.data?.detail || "Failed to run network discovery.");
        } finally {
            setIsScanning(false);
        }
    };

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [scanResults]);

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2><Search className="icon-lg text-blue" /> Network Scan Control Center</h2>
                    <p className="subtitle">Native CMD discovery of active endpoints and network neighbors</p>
                </div>
                <button
                    className={`btn-modern-primary ${isScanning ? 'disabled' : ''}`}
                    onClick={runDiscovery}
                    disabled={isScanning}
                >
                    {isScanning ? <RefreshCw className="spin" size={16} /> : <Search size={16} />}
                    {isScanning ? 'SCANNING NETWORK...' : 'INITIALIZE NETWORK DISCOVERY'}
                </button>
            </header>

            {error && (
                <div className="alert-item danger">
                    <AlertCircle size={18} /> {error}
                </div>
            )}

            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                {/* Raw CMD Output */}
                <div className="card terminal-card" style={{ background: '#0a0a0a', border: '1px solid #333' }}>
                    <div className="card-header" style={{ borderBottom: '1px solid #222', padding: '10px 15px' }}>
                        <h3 style={{ fontSize: '0.9rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Terminal size={16} /> SYSTEM CMD OUTPUT: {scanResults?.target_command || 'NULL'}
                        </h3>
                    </div>
                    <div
                        className="terminal-content"
                        ref={terminalRef}
                    >
                        {isScanning ? (
                            <div className="blink">Executing Shell Command...</div>
                        ) : scanResults ? (
                            <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{scanResults.raw_cmd_output}</pre>
                        ) : (
                            <div className="text-muted">Terminal ready. Click 'Initialize' to start scanning.</div>
                        )}
                    </div>
                </div>

                {/* Structured Data View */}
                <div className="card">
                    <div className="card-header">
                        <h3><Shield size={18} className="text-blue" /> Discovered Active Endpoints</h3>
                    </div>
                    <div className="table-responsive" style={{ height: '400px', overflowY: 'auto' }}>
                        {isScanning ? (
                            <div className="loading-container" style={{ padding: '50px', textAlign: 'center' }}>
                                <RefreshCw className="spin text-blue" size={32} />
                                <p className="text-muted mt-2">Parsing network packets...</p>
                            </div>
                        ) : scanResults?.structured_data?.length > 0 ? (
                            <table className="table-unified">
                                <thead>
                                    <tr>
                                        <th>Endpoint</th>
                                        <th>Network ID</th>
                                        <th>User Login</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {scanResults.structured_data.map((ep, idx) => (
                                        <tr key={idx}>
                                            <td>
                                                <div className="font-bold">{ep.hostname}</div>
                                                <div className="text-muted text-xs">MAC: {ep.mac_address}</div>
                                            </td>
                                            <td>
                                                <div className="font-mono">{ep.ip_address}</div>
                                            </td>
                                            <td>
                                                <div className="text-white">{ep.logged_in_user}</div>
                                                <div className="text-muted text-xs">{ep.employee_id}</div>
                                            </td>
                                            <td>
                                                <span className="badge badge-success">ONLINE</span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        ) : (
                            <div className="text-center" style={{ padding: '50px' }}>
                                <p className="text-muted">No active endpoint sessions detected in this scan.</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkScanner;
