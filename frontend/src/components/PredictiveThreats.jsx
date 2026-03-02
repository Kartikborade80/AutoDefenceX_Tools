import React, { useState, useEffect } from 'react';
import { TrendingUp, AlertTriangle, ShieldCheck, Activity, ShieldAlert, Zap, Search, ChevronDown, ChevronUp, Lock, Globe, Server, UserX, Cpu } from 'lucide-react';
import axios from '../api';
import './Dashboard.css';

const MOCK_ALERTS = [
    { id: 1, type: 'Network', title: 'Suspicious Outbound Traffic', description: 'Unusual spike in encrypted traffic to unknown IP 185.20.14.X detected.', severity: 'High', time: '2 mins ago', icon: Globe },
    { id: 2, type: 'Identity', title: 'Multiple Failed Logins', description: '5 failed admin login attempts from unauthorized geolocation.', severity: 'Critical', time: '15 mins ago', icon: UserX },
    { id: 3, type: 'Endpoint', title: 'Unauthorized Execution', description: 'powershell.exe executed with suspicious encoded payload on Workstation-04.', severity: 'Critical', time: '1 hr ago', icon: Zap },
    { id: 4, type: 'Network', title: 'Port Scan Detected', description: 'Sequential port scan originates from Internal Subnet A.', severity: 'Medium', time: '3 hrs ago', icon: Search },
    { id: 5, type: 'System', title: 'CPU Usage Anomaly', description: 'Server-DB-01 experiencing sustained 99% CPU load without corresponding network requests.', severity: 'Medium', time: '5 hrs ago', icon: Cpu }
];

const THREAT_LIBRARY = [
    { id: 'ransomware', name: 'Ransomware', category: 'Malware', risk: 'Critical', description: 'Malicious software designed to block access to a computer system or encrypt data until a sum of money is paid.', mitigation: 'Maintain offline and immutable backups, deploy advanced Endpoint Detection and Response (EDR), and disable public RDP access.' },
    { id: 'apt', name: 'Advanced Persistent Threat (APT)', category: 'Network', risk: 'Critical', description: 'A prolonged and targeted cyberattack in which an intruder gains access to a network and remains undetected for an extended period to steal continuous data.', mitigation: 'Implement Zero Trust Architecture, continuous network traffic analysis, and strict Identity and Access Management (IAM).' },
    { id: 'ddos', name: 'Distributed Denial of Service (DDoS)', category: 'Availability', risk: 'High', description: 'A malicious attempt to disrupt the normal traffic of a targeted server, service or network by overwhelming the target with a flood of Internet traffic.', mitigation: 'Utilize DDoS protection and scrubbing services, implement rate limiting, and design Anycast network topologies.' },
    { id: 'phishing', name: 'Spear Phishing', category: 'Social Engineering', risk: 'High', description: 'An email or electronic communications scam targeted towards a specific individual, organization, or business to steal sensitive information.', mitigation: 'Conduct regular employee security awareness training, deploy strict email filtering and SPF/DKIM/DMARC protocols, and enforce MFA.' },
    { id: 'zeroday', name: 'Zero-Day Exploit', category: 'Vulnerability', risk: 'Critical', description: 'A cyber attack that occurs on the same day a weakness is discovered in software, before a fix or patch is available from the vendor.', mitigation: 'Deploy behavioral-based intrusion prevention systems (IPS), utilize micro-segmentation, and establish rapid out-of-band patch management.' },
    { id: 'insider', name: 'Insider Threat', category: 'Identity', risk: 'High', description: 'A security risk that originates from within the targeted organization, typically involving employees or contractors misusing authorized access.', mitigation: 'Enforce Principle of Least Privilege, implement User and Entity Behavior Analytics (UEBA), and monitor data exfiltration vectors (DLP).' }
];

const PredictiveThreats = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [expandedThreat, setExpandedThreat] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get('/analytics/benchmarks', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setData(res.data);
            } catch (err) {
                console.error("Failed to fetch predictive analytics", err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);

    const toggleThreat = (id) => {
        setExpandedThreat(expandedThreat === id ? null : id);
    };

    const getSeverityColor = (severity) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'var(--danger)';
            case 'high': return '#f59e0b'; // warning orange
            case 'medium': return 'var(--primary)';
            default: return 'var(--success)';
        }
    };

    if (loading) {
        return (
            <div className="dashboard-container fade-in">
                <header className="dashboard-header">
                    <h2><TrendingUp className="icon-lg" /> Predictive Threat Analytics</h2>
                </header>
                <div className="loading-container">
                    <Activity className="spin text-blue" size={48} />
                    <p style={{ marginTop: '15px', color: '#94a3b8' }}>Analyzing Global Threat Vectors...</p>
                </div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="dashboard-container fade-in">
                <header className="dashboard-header">
                    <h2><TrendingUp className="icon-lg" /> Predictive Threat Analytics</h2>
                </header>
                <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
                    <AlertTriangle size={48} className="text-red" style={{ marginBottom: '20px' }} />
                    <h3>Unable to Load Analytics</h3>
                    <p style={{ color: 'var(--text-secondary)' }}>Could not retrieve data from the security intelligence engine.</p>
                </div>
            </div>
        );
    }

    const insights = data.insights || [];
    const topInsight = insights.find(i => i.score < i.benchmark) || insights[0] || {
        category: 'General Infrastructure',
        score: 0,
        benchmark: 100,
        recommendation: 'Perform a comprehensive security audit.'
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><TrendingUp className="icon-lg" /> Predictive Threat Analytics</h2>
                <div className="header-meta">
                    <span className="badge red pulse">LIVE THREAT FEED ACTIVE</span>
                </div>
            </header>

            <div className="metrics-grid-enhanced" style={{ marginBottom: '20px' }}>
                <div className="metric-card primary">
                    <div className="metric-header"><Activity size={16} /> GLOBAL RANK</div>
                    <div className="metric-value">{data.global_rank}</div>
                    <div className="metric-subtitle">vs Industry Peers</div>
                </div>
                <div className="metric-card success">
                    <div className="metric-header"><ShieldCheck size={16} /> INDUSTRY PERCENTILE</div>
                    <div className="metric-value">{data.industry_percentile}%</div>
                    <div className="metric-subtitle">Security Maturity Score</div>
                </div>
            </div>

            <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>

                {/* Left Column: AI Forecast and Alerts */}
                <div className="grid-column">
                    <div className="card full-width" style={{ marginBottom: '20px' }}>
                        <h3><AlertTriangle className="text-red" size={20} style={{ marginRight: '10px', verticalAlign: 'bottom' }} /> Critical Risk Forecast</h3>
                        <p style={{ fontSize: '1.1em', marginBottom: '15px', lineHeight: '1.5' }}>
                            AI Analysis indicates <strong className="text-red">Elevated Risk</strong> in {topInsight.category}.
                            Your score of <strong>{topInsight.score}</strong> is below the generic benchmark of <strong>{topInsight.benchmark}</strong>.
                        </p>

                        <div className="alert-item warning" style={{ marginTop: '15px' }}>
                            <Zap size={20} color="#f59e0b" style={{ marginRight: '10px' }} />
                            <span><strong>Recommendation:</strong> {topInsight.recommendation}</span>
                        </div>
                    </div>

                    <div className="card full-width">
                        <h3><Activity size={20} style={{ marginRight: '10px', verticalAlign: 'bottom' }} /> Real-Time Threat Alerts</h3>
                        <p style={{ color: 'var(--text-secondary)', marginBottom: '15px', fontSize: '0.9rem' }}>
                            Multi-vector live simulated threat detection stream.
                        </p>
                        <div className="alerts-feed" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                            {MOCK_ALERTS.map(alert => {
                                const Icon = alert.icon || Activity;
                                const color = getSeverityColor(alert.severity);
                                return (
                                    <div key={alert.id} className="glass-panel" style={{
                                        padding: '15px',
                                        borderRadius: '8px',
                                        borderLeft: `4px solid ${color}`,
                                        display: 'flex',
                                        gap: '15px',
                                        alignItems: 'flex-start',
                                        background: 'rgba(255, 255, 255, 0.02)'
                                    }}>
                                        <div style={{ padding: '10px', background: `${color}15`, borderRadius: '50%', color: color }}>
                                            {Icon && <Icon size={20} />}
                                        </div>
                                        <div style={{ flex: 1 }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
                                                <h4 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)' }}>{alert.title}</h4>
                                                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{alert.time}</span>
                                            </div>
                                            <p style={{ margin: '0 0 10px 0', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{alert.description}</p>
                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                <span className="badge" style={{ background: `${color}20`, color: color, fontSize: '0.75rem', padding: '2px 6px' }}>{alert.severity}</span>
                                                <span className="badge" style={{ background: 'rgba(255,255,255,0.1)', fontSize: '0.75rem', padding: '2px 6px' }}>{alert.type} Vector</span>
                                            </div>
                                        </div>
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                </div>

                {/* Right Column: Threat Intel Library */}
                <div className="grid-column">
                    <div className="card full-width" style={{ height: '100%' }}>
                        <h3><ShieldAlert size={20} style={{ marginRight: '10px', verticalAlign: 'bottom' }} /> Threat Intelligence Library</h3>
                        <p style={{ color: 'var(--text-secondary)', marginBottom: '15px', fontSize: '0.9rem' }}>
                            Comprehensive encyclopedia of modern cyber threats and mitigation strategies.
                        </p>

                        <div className="threat-library-accordion" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            {THREAT_LIBRARY.map((threat) => (
                                <div key={threat.id} className="glass-panel" style={{ borderRadius: '8px', overflow: 'hidden' }}>
                                    <div
                                        onClick={() => toggleThreat(threat.id)}
                                        style={{
                                            padding: '15px',
                                            cursor: 'pointer',
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            alignItems: 'center',
                                            background: expandedThreat === threat.id ? 'rgba(255,255,255,0.05)' : 'transparent',
                                            transition: 'background 0.2s ease'
                                        }}
                                    >
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                            <Lock size={18} className={threat.risk === 'Critical' ? 'text-red' : 'text-yellow'} />
                                            <h4 style={{ margin: 0 }}>{threat.name}</h4>
                                        </div>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                            <span className="badge" style={{ fontSize: '0.75rem', padding: '2px 8px', background: 'rgba(255,255,255,0.1)' }}>{threat.category}</span>
                                            {expandedThreat === threat.id ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                                        </div>
                                    </div>

                                    {expandedThreat === threat.id && (
                                        <div style={{ padding: '0 15px 15px 15px', animation: 'fadeIn 0.3s ease' }}>
                                            <div style={{ height: '1px', background: 'rgba(255,255,255,0.1)', width: '100%', marginBottom: '15px' }}></div>
                                            <div style={{ marginBottom: '15px' }}>
                                                <h5 style={{ color: 'var(--primary)', marginBottom: '5px', fontSize: '0.9rem' }}>Threat Description</h5>
                                                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.5', margin: 0 }}>
                                                    {threat.description}
                                                </p>
                                            </div>
                                            <div style={{ background: 'rgba(16, 185, 129, 0.05)', padding: '10px', borderRadius: '6px', borderLeft: '3px solid var(--success)' }}>
                                                <h5 style={{ color: 'var(--success)', marginBottom: '5px', fontSize: '0.9rem' }}>Required Mitigation</h5>
                                                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.5', margin: 0 }}>
                                                    {threat.mitigation}
                                                </p>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default PredictiveThreats;
