import React, { useEffect, useState } from 'react';
import axios from '../api';
import { Cpu, CircuitBoard, Database, Monitor, Server, Clock } from 'lucide-react';
import './Dashboard.css'; // Reusing dashboard styles for consistency

const SystemInfo = () => {
    const [info, setInfo] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchInfo = async () => {
        try {
            setLoading(true);
            const token = localStorage.getItem('token');
            const res = await axios.get('/system/info', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setInfo(res.data);
            setLoading(false);
        } catch (err) {
            console.error(err);
            setError("Failed to load system information.");
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchInfo();
    }, []);

    if (loading) {
        return (
            <div className="dashboard-container fade-in">
                <div className="loading-state-container">
                    <div className="loading-spinner-wrapper">
                        <div className="loading-spinner"></div>
                        <p className="loading-text">Loading System Information...</p>
                        <p className="loading-subtext">Fetching hardware and OS details</p>
                        <p style={{ marginTop: '15px', fontSize: '0.85rem', color: '#f59e0b', fontWeight: '500' }}>
                            ⏱️ System queries can take 20-40 seconds. Please wait...
                        </p>
                    </div>
                </div>
            </div>
        );
    }
    if (error) return <div className="error-message">{error}</div>;

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2><Monitor className="icon" /> System Specifications</h2>
                    <p className="subtitle">Original Host Hardware Data</p>
                </div>
                <div className="status-indicator">
                    <div style={{ fontFamily: 'monospace', fontSize: '0.9rem', color: '#94a3b8' }}>
                        {info.hostname}
                    </div>
                </div>
            </header>

            <div className="dashboard-grid">
                {/* OS & Architecture */}
                <div className="card full-width" style={{ background: 'linear-gradient(145deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.8))' }}>
                    <div className="card-header">
                        <h3><Server size={22} color="#38bdf8" /> Operating System</h3>
                    </div>
                    <div className="metric-value" style={{ fontSize: '1.5rem', marginTop: '10px' }}>{info.os.name}</div>
                    <div className="metric-subtitle" style={{ marginBottom: '15px' }}>{info.os.version}</div>

                    <div style={{ display: 'flex', gap: '15px' }}>
                        <span className="badge badge-info">{info.os.arch}</span>
                    </div>
                </div>

                {/* CPU Specs */}
                <div className="card" style={{ borderTop: '3px solid #f472b6' }}>
                    <div className="card-header">
                        <h3><Cpu size={22} color="#f472b6" /> Processor</h3>
                    </div>
                    <div className="desc">
                        <strong style={{ display: 'block', fontSize: '1.1rem', marginBottom: '8px' }}>{info.cpu.name}</strong>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
                            <div className="stat-box" style={{ background: 'rgba(255,255,255,0.05)', padding: '10px', borderRadius: '8px' }}>
                                <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>Cores</div>
                                <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{info.cpu.cores}</div>
                            </div>
                            <div className="stat-box" style={{ background: 'rgba(255,255,255,0.05)', padding: '10px', borderRadius: '8px' }}>
                                <div style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>Threads</div>
                                <div style={{ fontSize: '1.2rem', fontWeight: 'bold' }}>{info.cpu.logical}</div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* RAM Specs */}
                <div className="card" style={{ borderTop: '3px solid #34d399' }}>
                    <div className="card-header">
                        <h3><CircuitBoard size={22} color="#34d399" /> Memory (RAM)</h3>
                    </div>

                    <div style={{ marginTop: '10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                            <span style={{ color: '#94a3b8' }}>Usage</span>
                            <span style={{ fontWeight: 'bold' }}>{info.ram.percent_used}%</span>
                        </div>
                        <div style={{ width: '100%', height: '8px', background: '#334155', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{ width: `${info.ram.percent_used}%`, height: '100%', background: '#34d399' }}></div>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '15px', fontSize: '0.9rem' }}>
                            <div>
                                <div style={{ color: '#94a3b8' }}>Total</div>
                                <div>{info.ram.total_gb} GB</div>
                            </div>
                            <div style={{ textAlign: 'right' }}>
                                <div style={{ color: '#94a3b8' }}>Free</div>
                                <div>{info.ram.free_gb} GB</div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Raw API Dump (for "Original Data" confirmation) */}
                <div className="card full-width">
                    <div className="card-header">
                        <h3><Database size={22} /> Raw System Data</h3>
                    </div>
                    <div style={{ maxHeight: '200px', overflowY: 'auto', background: 'rgba(0,0,0,0.3)', padding: '15px', borderRadius: '8px', fontFamily: 'monospace', fontSize: '0.85rem', color: '#e2e8f0' }}>
                        <pre>{JSON.stringify(info, null, 2)}</pre>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SystemInfo;
