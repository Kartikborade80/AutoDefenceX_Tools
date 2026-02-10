import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api';
import {
    Monitor,
    Cpu,
    HardDrive,
    Shield,
    ShieldAlert,
    ShieldCheck,
    Activity,
    History,
    ArrowLeft,
    RefreshCw,
    Database,
    Binary,
    Zap,
    Terminal,
    Power
} from 'lucide-react';
import './EndpointDetail.css';
import './DashboardEnhanced.css';

const EndpointDetail = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [endpoint, setEndpoint] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [loadingVulns, setLoadingVulns] = useState(false);

    useEffect(() => {
        fetchEndpointDetails();
        fetchVulnerabilities();
    }, [id]);

    const fetchEndpointDetails = async () => {
        // ... (existing fetch)
        try {
            setLoading(true);
            const response = await api.get(`/endpoints/${id}`);
            setEndpoint(response.data);
            setLoading(false);
        } catch (err) {
            console.error("Error fetching endpoint details:", err);
            setError("Failed to load endpoint details. Please try again.");
            setLoading(false);
        }
    };

    const fetchVulnerabilities = async () => {
        try {
            setLoadingVulns(true);
            const response = await api.get(`/analytics/vulnerabilities/${id}`);
            setVulnerabilities(response.data.vulnerabilities || []);
        } catch (err) {
            console.error("Error fetching vulnerabilities:", err);
        } finally {
            setLoadingVulns(false);
        }
    };

    const handleKillProcess = async (pid, processName) => {
        if (!window.confirm(`Are you sure you want to terminate process "${processName}" (PID: ${pid})?`)) return;

        try {
            await api.post(`/endpoints/${id}/kill-process/${pid}`);
            alert(`Process ${processName} terminated successfully.`);
            fetchEndpointDetails(); // Refresh the list
        } catch (err) {
            console.error("Failed to kill process:", err);
            alert("Failed to terminate process. It might have already ended or requires higher privileges.");
        }
    };

    const getRiskBadge = (level) => {
        const colors = {
            low: 'badge-green',
            medium: 'badge-yellow',
            high: 'badge-orange',
            critical: 'badge-red'
        };
        return <span className={`badge ${colors[level] || 'badge-blue'}`}>{level.toUpperCase()}</span>;
    };

    if (loading) {
        return (
            <div className="detail-loading">
                <RefreshCw className="spin icon-lg" />
                <p>Decrypting endpoint data...</p>
            </div>
        );
    }

    if (error || !endpoint) {
        return (
            <div className="detail-error">
                <ShieldAlert className="icon-xl text-red" />
                <h2>{error || "Endpoint not found"}</h2>
                <button className="cyber-button" onClick={() => navigate('/endpoints')}>
                    <ArrowLeft size={18} /> Back to Endpoints
                </button>
            </div>
        );
    }

    const { system_info, scans, alerts } = endpoint;

    return (
        <div className="endpoint-detail-container fade-in">
            <header className="detail-header">
                <button className="back-btn" onClick={() => navigate('/endpoints')}>
                    <ArrowLeft size={20} />
                </button>
                <div className="header-info">
                    <h1><Monitor className="icon-lg" /> {endpoint.hostname}</h1>
                    <div className="header-meta">
                        <span className={`status-dot ${endpoint.status}`}></span>
                        <span className="text-secondary">{endpoint.ip_address}</span>
                        {getRiskBadge(endpoint.risk_level)}
                    </div>
                </div>
                <div className="header-actions">
                    <button className="cyber-button secondary" onClick={fetchEndpointDetails}>
                        <RefreshCw size={18} /> Refresh
                    </button>
                    <button className="cyber-button primary">
                        <Shield size={18} /> Full Scan
                    </button>
                </div>
            </header>

            <div className="detail-grid">
                {/* Hardware & System Info */}
                <section className="detail-card system-info-card">
                    <div className="card-header">
                        <h2><Database size={20} /> System Infrastructure</h2>
                    </div>
                    <div className="metrics-row">
                        <div className="metric-item">
                            <Cpu size={24} className="text-blue" />
                            <div className="metric-value">
                                <h3>{system_info?.cpu_usage || 0}%</h3>
                                <p>CPU Load</p>
                            </div>
                        </div>
                        <div className="metric-item">
                            <Binary size={24} className="text-purple" />
                            <div className="metric-value">
                                <h3>{system_info?.ram_usage || 0} GB</h3>
                                <p>RAM Used ({system_info?.total_ram || 0} GB Total)</p>
                            </div>
                        </div>
                        <div className="metric-item">
                            <HardDrive size={24} className="text-orange" />
                            <div className="metric-value">
                                <h3>{Object.keys(system_info?.disk_usage || {}).length} Drives</h3>
                                <p>Detected storage</p>
                            </div>
                        </div>
                    </div>
                    <div className="os-details">
                        <p><strong>OS Distribution:</strong> {endpoint.os_details || 'Windows 11 Pro'}</p>
                        <p><strong>MAC Address:</strong> {endpoint.mac_address || 'N/A'}</p>
                        <p><strong>Trust Score:</strong> <span className="text-green">{endpoint.trust_score}%</span></p>
                    </div>
                </section>

                {/* Security Health */}
                <section className="detail-card security-card">
                    <div className="card-header">
                        <h2><ShieldCheck size={20} /> Security Posture</h2>
                    </div>
                    <div className="security-score">
                        <div className="score-ring">
                            <svg viewBox="0 0 36 36">
                                <path className="ring-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                                <path className="ring-fill" strokeDasharray={`${endpoint.trust_score}, 100`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            </svg>
                            <span className="score-text">{endpoint.trust_score}</span>
                        </div>
                        <div className="score-info">
                            <h3>Integrity Rating</h3>
                            <p>{endpoint.trust_score > 80 ? 'Optimal protection level achieved.' : 'Vulnerabilities detected. Action required.'}</p>
                        </div>
                    </div>
                    <div className="quick-actions">
                        <h4>Containment Protocols</h4>
                        <div className="action-btns">
                            <button className="cyber-button danger mini">ISOLATE ENDPOINT</button>
                            <button className="cyber-button warning mini">RESTRICT ACCESS</button>
                        </div>
                    </div>
                </section>

                {/* Live Alerts */}
                <section className="detail-card alerts-column">
                    <div className="card-header">
                        <h2><ShieldAlert size={20} /> Security Incidents</h2>
                    </div>
                    <div className="alerts-list">
                        {alerts?.length > 0 ? alerts.map(alert => (
                            <div key={alert.id} className={`alert-item-mini ${alert.severity}`}>
                                <div className="alert-top">
                                    <span className="alert-title">{alert.title}</span>
                                    <span className="alert-time">{new Date(alert.created_at).toLocaleTimeString()}</span>
                                </div>
                                <p className="alert-desc">{alert.description}</p>
                            </div>
                        )) : (
                            <div className="empty-state">
                                <ShieldCheck size={32} className="text-green" />
                                <p>No active threats detected.</p>
                            </div>
                        )}
                    </div>
                </section>

                {/* Scan History */}
                <section className="detail-card scans-column">
                    <div className="card-header">
                        <h2><History size={20} /> Inspection History</h2>
                    </div>
                    <div className="scans-list">
                        {scans?.length > 0 ? scans.map(scan => (
                            <div key={scan.id} className="scan-record">
                                <Activity size={16} className="text-blue" />
                                <div className="scan-info">
                                    <span className="scan-type">{scan.scan_type.toUpperCase()} SCAN</span>
                                    <span className="scan-date">{new Date(scan.started_at).toLocaleDateString()}</span>
                                </div>
                                <span className={`scan-status ${scan.status}`}>{scan.status}</span>
                                <span className="scan-count">{scan.threat_count} Threats</span>
                            </div>
                        )) : (
                            <div className="empty-state">
                                <Zap size={32} className="text-secondary" />
                                <p>No scan history available.</p>
                            </div>
                        )}
                    </div>
                </section>

                {/* Software & Vulnerabilities */}
                <section className="detail-card full-width">
                    <div className="card-header">
                        <h2><Binary size={20} /> Software Inventory & Vulnerability Mapping</h2>
                    </div>
                    <div className="vuln-section-layout">
                        <div className="software-list-box">
                            <h4>Installed Applications</h4>
                            <ul className="mono-list">
                                {system_info?.installed_software?.map((sw, idx) => (
                                    <li key={idx}>{sw}</li>
                                ))}
                            </ul>
                        </div>
                        <div className="vulnerability-box">
                            <h4>Active CVE Threats {loadingVulns && <RefreshCw size={12} className="spin" />}</h4>
                            {vulnerabilities.length > 0 ? (
                                <div className="vuln-items">
                                    {vulnerabilities.map((v, idx) => (
                                        <div key={idx} className={`vuln-notice ${v.severity}`}>
                                            <div className="vuln-header">
                                                <span className="cve-id">{v.cve}</span>
                                                <span className={`badge badge-micro ${v.severity}`}>{v.severity.toUpperCase()}</span>
                                            </div>
                                            <p className="vuln-software"><strong>Impacts:</strong> {v.software}</p>
                                            <p className="vuln-desc">{v.description}</p>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="empty-state">
                                    <ShieldCheck size={24} className="text-green" />
                                    <p>No known vulnerabilities mapped to installed software.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </section>

                {/* Running Processes */}
                <section className="detail-card processes-column full-width-mobile">
                    {/* ... existing processes code ... */}
                    <div className="card-header">
                        <h2><Terminal size={20} /> Active Processes</h2>
                    </div>
                    <div className="process-list">
                        {system_info?.running_processes?.length > 0 ? system_info.running_processes.map((proc, idx) => (
                            <div key={idx} className="process-item">
                                <div className="proc-main">
                                    <span className="proc-name">{proc.Name}</span>
                                    <span className="proc-pid">PID: {proc.Id}</span>
                                </div>
                                <div className="proc-stats">
                                    <span className="proc-cpu">CPU: {proc.CPU ? proc.CPU.toFixed(1) : 0}%</span>
                                    <span className="proc-mem">MEM: {(proc.WorkingSet / 1024 / 1024).toFixed(1)}MB</span>
                                </div>
                                <button
                                    className="cyber-button danger mini"
                                    title="Terminate Process"
                                    onClick={() => handleKillProcess(proc.Id, proc.Name)}
                                >
                                    <Power size={14} />
                                </button>
                            </div>
                        )) : (
                            <div className="empty-state">
                                <Activity size={32} className="text-secondary" />
                                <p>No process data available.</p>
                            </div>
                        )}
                    </div>
                </section>
            </div>
        </div>
    );
};

export default EndpointDetail;
