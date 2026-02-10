import React, { useState, useEffect } from 'react';
import { Monitor, Cpu, HardDrive, ShieldCheck, Activity } from 'lucide-react';
import './Dashboard.css';

const PCInfo = () => {
    // In a real app, this would fetch from the Agent API
    const [info] = useState({
        hostname: "DESKTOP-WORK-01",
        os: "Windows 11 Pro",
        cpu: "Intel Core i7-12700K",
        ram: "32 GB",
        disk: "1 TB SSD",
        riskScore: 3.5,
        protection: "Active"
    });

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2><Monitor className="icon-lg" /> System Information</h2>
                    <p className="subtitle">Device Telemetry & Hardware Specs</p>
                </div>
                <div className="status-indicator">
                    <span className="dot pulse"></span>
                    ONLINE
                </div>
            </header>

            <div className="metrics-grid-enhanced">
                <div className="metric-card primary">
                    <div className="metric-header">
                        <Monitor size={24} />
                        <span className="metric-label">Hostname</span>
                    </div>
                    <div className="metric-value" style={{ fontSize: '1.5rem' }}>{info.hostname}</div>
                    <div className="metric-subtitle">Domain Joined</div>
                </div>

                <div className="metric-card info">
                    <div className="metric-header">
                        <HardDrive size={24} />
                        <span className="metric-label">OS Build</span>
                    </div>
                    <div className="metric-value" style={{ fontSize: '1.5rem' }}>{info.os}</div>
                    <div className="metric-subtitle">22H2 (OS Build 22621.1702)</div>
                </div>

                <div className="metric-card success">
                    <div className="metric-header">
                        <ShieldCheck size={24} />
                        <span className="metric-label">Security Score</span>
                    </div>
                    <div className="metric-value">{10 - info.riskScore}/10</div>
                    <div className="metric-subtitle">High Compliance</div>
                </div>
            </div>

            <div className="dashboard-grid">
                <div className="card full-width">
                    <div className="card-header">
                        <h3><Cpu size={22} /> Hardware Performance</h3>
                        <span className="badge badge-info">OPTIMAL</span>
                    </div>

                    <div className="details-grid" style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '20px',
                        padding: '10px'
                    }}>
                        <div className="detail-item glass-panel" style={{ padding: '20px', borderRadius: '12px', background: 'rgba(255,255,255,0.03)' }}>
                            <span className="label" style={{ display: 'block', marginBottom: '8px', color: '#94a3b8' }}>Processor</span>
                            <span className="value" style={{ fontSize: '1.1rem', fontWeight: '600', color: '#e2e8f0' }}>{info.cpu}</span>
                            <div className="health-bar-container" style={{ marginTop: '15px' }}>
                                <span>Load Average</span>
                                <div className="health-bar"><div className="fill blue" style={{ width: '15%' }}></div></div>
                            </div>
                        </div>

                        <div className="detail-item glass-panel" style={{ padding: '20px', borderRadius: '12px', background: 'rgba(255,255,255,0.03)' }}>
                            <span className="label" style={{ display: 'block', marginBottom: '8px', color: '#94a3b8' }}>Memory</span>
                            <span className="value" style={{ fontSize: '1.1rem', fontWeight: '600', color: '#e2e8f0' }}>{info.ram}</span>
                            <div className="health-bar-container" style={{ marginTop: '15px' }}>
                                <span>Usage</span>
                                <div className="health-bar"><div className="fill green" style={{ width: '42%' }}></div></div>
                            </div>
                        </div>

                        <div className="detail-item glass-panel" style={{ padding: '20px', borderRadius: '12px', background: 'rgba(255,255,255,0.03)' }}>
                            <span className="label" style={{ display: 'block', marginBottom: '8px', color: '#94a3b8' }}>Storage</span>
                            <span className="value" style={{ fontSize: '1.1rem', fontWeight: '600', color: '#e2e8f0' }}>{info.disk}</span>
                            <div className="health-bar-container" style={{ marginTop: '15px' }}>
                                <span>Used Space</span>
                                <div className="health-bar"><div className="fill blue" style={{ width: '68%' }}></div></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default PCInfo;
