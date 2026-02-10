import React, { useState, useEffect } from 'react';
import { Monitor, RefreshCw, Server, CheckCircle, XCircle, Clock, User, Activity, Shield, MessageSquare, ArrowRight, Power, Trash2, Terminal } from 'lucide-react';
import axios from '../api';
import useLiveData from '../hooks/useLiveData';
import { useNavigate } from 'react-router-dom';
import './Dashboard.css';

const EndpointList = () => {
    const [endpoints, setEndpoints] = useState([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    // Fetch active endpoints (which now returns session-linked data)
    const { data: liveEndpointData, loading: dataLoading } = useLiveData(async () => {
        const token = localStorage.getItem('token');
        const res = await axios.get('/endpoints/', {
            headers: { Authorization: `Bearer ${token}` }
        });
        return res.data;
    }, 5000);

    useEffect(() => {
        if (liveEndpointData) {
            setEndpoints(liveEndpointData);
            setLoading(false);
        } else if (!dataLoading) {
            setLoading(false);
        }
    }, [liveEndpointData, dataLoading]);

    const handleLogOut = async (sessionId) => {
        if (!window.confirm('Force logout this user from the endpoint?')) return;

        try {
            const token = localStorage.getItem('token');
            // Assuming the endpoints are linked to user sessions
            await axios.post(`/endpoints/terminate-session/${sessionId}`, {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            alert('User logged out successfully.');
            // Live update will handle the UI removal automatically
        } catch (err) {
            console.error('Failed to end session:', err);
            alert('Failed to terminate session');
        }
    };

    const handleMessageUser = (userId) => {
        navigate('/messages', { state: { openChatWith: userId } });
    };

    const handleViewDetails = (session) => {
        navigate(`/endpoints/${session.endpoint_id}`);
    };

    const handleDeleteRecord = async (sessionId) => {
        if (!window.confirm('Are you sure you want to remove this session record?')) return;
        // Mock delete for now as API might not support soft delete of session log directly
        // Or implement if backend supports it. For now, we perform the logout action which effectively removes it from "active"
        handleLogOut(sessionId);
    };

    const refreshData = () => {
        setLoading(true);
        // Live data hook will naturally fetch on next interval or we could trigger update if implemented
        // Since we're using live data, we just rely on the hook
        setLoading(false);
    };

    const handleDownloadAgent = async () => {
        try {
            const token = localStorage.getItem('token');
            const response = await axios.get('/endpoints/download-agent', {
                headers: { Authorization: `Bearer ${token}` },
                responseType: 'blob', // Important for file download
            });

            // Create blob link to download
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', 'DefaultRemoteOffice_Agent.exe');
            document.body.appendChild(link);
            link.click();
            link.remove();

            // Show instruction
            alert("Download Started!\n\nPlease configure the agent connection string matching this system.");
        } catch (error) {
            console.error("Download failed", error);
            alert("Failed to download agent installer.");
        }
    };

    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const role = userInfo.role;
    const departmentId = userInfo.department_id;

    if (role === 'Intern' || role === 'user') {
        return (
            <div className="dashboard-container fade-in">
                <header className="page-header">
                    <h2><Monitor className="icon" /> Endpoint Management</h2>
                </header>
                <div className="card full-width centered-content" style={{ padding: '80px', textAlign: 'center' }}>
                    <Shield size={64} className="text-red" style={{ marginBottom: '20px', opacity: 0.5 }} />
                    <h3 className="text-white">Access Restricted</h3>
                    <p className="text-muted">You are not eligible for this access.</p>
                </div>
            </div>
        );
    }

    // Filter endpoints for HOD / Manager
    const displayEndpoints = role === 'Admin' ? endpoints : endpoints.filter(e => e.department_id === departmentId || !e.department_id);

    return (
        <div className="dashboard-container fade-in">
            <header className="page-header">
                <h2><Monitor className="icon" /> {role === 'Admin' ? 'Global' : 'Department'} Endpoint Management</h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                    <button className="btn-modern-primary btn-modern-sm" onClick={handleDownloadAgent} style={{ backgroundColor: '#10b981', borderColor: '#10b981' }}>
                        <ArrowRight size={16} /> Download Agent
                    </button>
                    <button className="btn-modern-primary btn-modern-sm" onClick={refreshData}>
                        <RefreshCw size={16} /> Sync Surveillance
                    </button>
                </div>
            </header>

            {/* Statistics */}
            <div className="metrics-grid-enhanced" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: '30px' }}>
                <div className="metric-card primary">
                    <span className="metric-label">Monitored Nodes</span>
                    <div className="metric-value">{displayEndpoints.length}</div>
                </div>
                <div className="metric-card success">
                    <span className="metric-label">Status</span>
                    <div className="metric-value">Active</div>
                </div>
                <div className="metric-card info">
                    <span className="metric-label">Trust Index</span>
                    <div className="metric-value">94%</div>
                </div>
            </div>

            <div className="card full-width">
                <h3>{role === 'Admin' ? 'Enterprise Surveillance Feed' : 'Departmental Assets'}</h3>
                {loading ? (
                    <p>Loading endpoints...</p>
                ) : endpoints.length === 0 ? (
                    <p>No endpoints found.</p>
                ) : (
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Emp ID</th>
                                    <th>Full Name</th>
                                    <th>Department</th>
                                    <th>System / Host</th>
                                    <th>IP Address</th>
                                    <th>Status</th>
                                    <th>Active Since</th>
                                    <th className="text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {displayEndpoints.map((session) => {
                                    const sessionStart = session.session_start ? new Date(session.session_start) : new Date();

                                    return (
                                        <tr key={session.session_id}>
                                            <td className="text-blue mono">{session.employee_id}</td>
                                            <td>
                                                <div className="text-white font-medium">{session.full_name}</div>
                                                <div style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{session.job_title}</div>
                                            </td>
                                            <td><span className="badge badge-user">{session.department_name}</span></td>
                                            <td>
                                                <div className="text-white mono" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    <Terminal size={12} className="text-blue" />
                                                    <span>{session.hostname}</span>
                                                    <span className="badge badge-info" style={{ fontSize: '0.65rem', padding: '1px 5px' }}>
                                                        PROCESS CTRL
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="mono text-muted">{session.ip_address}</td>
                                            <td>
                                                <span className="badge badge-success">
                                                    <span className="live-dot"></span> ONLINE
                                                </span>
                                            </td>
                                            <td className="mono text-muted">
                                                {sessionStart.toLocaleTimeString()}
                                            </td>
                                            <td className="text-right">
                                                <div className="action-buttons-row" style={{ justifyContent: 'flex-end', display: 'flex', gap: '8px' }}>
                                                    {/* Message Button */}
                                                    <button
                                                        className="btn-icon-blue"
                                                        title="Message User"
                                                        onClick={() => handleMessageUser(session.user_id)}
                                                    >
                                                        <MessageSquare size={16} />
                                                    </button>

                                                    <button
                                                        className="btn-icon-orange"
                                                        title="Remote Control & Details"
                                                        onClick={() => handleViewDetails(session)}
                                                    >
                                                        <Activity size={16} />
                                                    </button>

                                                    {/* Logout Button */}
                                                    <button
                                                        className="btn-icon-red"
                                                        title="Force Logout"
                                                        onClick={() => handleLogOut(session.session_id)}
                                                    >
                                                        <Power size={16} />
                                                    </button>

                                                    {/* Delete Button (optional based on screenshot interpretation) */}
                                                    {/* <button 
                                                        className="btn-icon-danger-soft" 
                                                        title="Remove Record"
                                                        onClick={() => handleDeleteRecord(session.session_id)}
                                                    >
                                                        <Trash2 size={16} />
                                                    </button> */}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            <style>{`
                .text-right { text-align: right; }
                .btn-icon-blue {
                    background: #3b82f6;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                }
                .btn-icon-blue:hover { background: #2563eb; }

                .btn-icon-orange {
                    background: #f59e0b;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                }
                .btn-icon-orange:hover { background: #d97706; }

                .btn-icon-red {
                    background: #ef4444;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 10px;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                }
                .btn-icon-red:hover { background: #dc2626; }

                .btn-icon-danger-soft {
                    background: rgba(239, 68, 68, 0.1);
                    color: #ef4444;
                    border: 1px solid rgba(239, 68, 68, 0.2);
                    border-radius: 6px;
                    padding: 6px 10px;
                    cursor: pointer;
                    transition: all 0.2s;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                }
                .btn-icon-danger-soft:hover { background: rgba(239, 68, 68, 0.2); }
            `}</style>
        </div>
    );
};

export default EndpointList;
