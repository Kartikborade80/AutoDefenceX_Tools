import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Search, Filter, Calendar, User, AlertTriangle, CheckCircle, Clock, Shield } from 'lucide-react';
import './Dashboard.css';

const Forensics = () => {
    const [logs, setLogs] = useState([]);
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(false);
    const [filters, setFilters] = useState({
        user_id: '',
        event_type: '',
        start_date: '',
        end_date: ''
    });
    const [stats, setStats] = useState(null);

    const ensureUTC = (timestamp) => {
        if (!timestamp) return '';
        return timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
    };

    useEffect(() => {
        fetchUsers();
        fetchStats();
        fetchLogs();

        // Implement polling for live updates
        const interval = setInterval(() => {
            fetchStats();
            fetchLogs();
            console.log('Forensics: Polling for updates...');
        }, 15000); // Every 15 seconds

        return () => clearInterval(interval);
    }, []);

    const fetchUsers = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/users/', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setUsers(res.data);
        } catch (err) {
            console.error('Failed to fetch users', err);
        }
    };

    const fetchStats = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/forensics/stats', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setStats(res.data);
        } catch (err) {
            console.error('Failed to fetch stats', err);
        }
    };

    const fetchLogs = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const params = new URLSearchParams();
            if (filters.user_id) params.append('user_id', filters.user_id);
            if (filters.event_type) params.append('event_type', filters.event_type);
            if (filters.start_date) params.append('start_date', filters.start_date);
            if (filters.end_date) params.append('end_date', filters.end_date);

            const res = await axios.get(`/forensics/?${params.toString()}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setLogs(res.data);
        } catch (err) {
            console.error('Failed to fetch forensic logs', err);
        } finally {
            setLoading(false);
        }
    };

    const handleFilterChange = (key, value) => {
        setFilters(prev => ({ ...prev, [key]: value }));
    };

    const handleSearch = () => {
        fetchLogs();
    };

    const clearFilters = () => {
        setFilters({
            user_id: '',
            event_type: '',
            start_date: '',
            end_date: ''
        });
        setTimeout(() => fetchLogs(), 100);
    };

    const getEventIcon = (eventType) => {
        switch (eventType) {
            case 'login':
                return <CheckCircle size={16} className="text-green" />;
            case 'failed_login':
                return <AlertTriangle size={16} className="text-red" />;
            case 'logout':
                return <Clock size={16} className="text-blue" />;
            default:
                return <Shield size={16} className="text-yellow" />;
        }
    };

    const getEventBadgeClass = (eventType) => {
        switch (eventType) {
            case 'login':
                return 'badge badge-success';
            case 'failed_login':
                return 'error-badge';
            case 'logout':
                return 'badge badge-user';
            default:
                return 'badge badge-warning';
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><Search className="icon-lg" /> Digital Forensics & Timeline</h2>
                <div className="badge pulse green" style={{ padding: '8px 15px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div className="dot" style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#fff', animation: 'pulse 1.5s infinite' }}></div>
                    LIVE UPDATES
                </div>
            </header>

            {/* Statistics Cards */}
            {stats && (
                <div className="stats-grid">
                    <div className="metric-box blue-border">
                        <h4>Total Events</h4>
                        <p>{stats.total_logs}</p>
                    </div>
                    {Object.entries(stats.event_type_counts).map(([type, count]) => (
                        <div key={type} className={`metric-box ${type === 'failed_login' ? 'red-border' : 'green-border'}`}>
                            <h4>{type.replace('_', ' ').toUpperCase()}</h4>
                            <p>{count}</p>
                        </div>
                    ))}
                </div>
            )}

            {/* Filters */}
            <div className="card full-width">
                <h3><Filter size={20} /> Filter Events</h3>
                <div className="report-controls" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
                    <div className="form-group">
                        <label><User size={16} /> User</label>
                        <select
                            className="cyber-input"
                            value={filters.user_id}
                            onChange={e => handleFilterChange('user_id', e.target.value)}
                        >
                            <option value="">All Users</option>
                            {users.map(user => (
                                <option key={user.id} value={user.id}>
                                    {user.full_name || user.username}
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="form-group">
                        <label>Event Type</label>
                        <select
                            className="cyber-input"
                            value={filters.event_type}
                            onChange={e => handleFilterChange('event_type', e.target.value)}
                        >
                            <option value="">All Events</option>
                            <option value="login">Login</option>
                            <option value="failed_login">Failed Login</option>
                            <option value="logout">Logout</option>
                            <option value="suspicious_activity">Suspicious Activity</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label><Calendar size={16} /> Start Date</label>
                        <input
                            type="date"
                            className="cyber-input"
                            value={filters.start_date}
                            onChange={e => handleFilterChange('start_date', e.target.value)}
                        />
                    </div>

                    <div className="form-group">
                        <label><Calendar size={16} /> End Date</label>
                        <input
                            type="date"
                            className="cyber-input"
                            value={filters.end_date}
                            onChange={e => handleFilterChange('end_date', e.target.value)}
                        />
                    </div>

                    <div className="btn-container-centered">
                        <button className="btn-modern-primary btn-modern-sm" onClick={handleSearch}>
                            <Search size={16} /> Search
                        </button>
                        <button className="btn-modern-secondary btn-modern-sm" onClick={clearFilters}>
                            Clear
                        </button>
                    </div>
                </div>
            </div>

            {/* Timeline */}
            <div className="card full-width">
                <h3><Clock size={20} /> Event Timeline</h3>
                {loading ? (
                    <div className="loading-state">Loading forensic logs...</div>
                ) : logs.length === 0 ? (
                    <div className="empty-state">No forensic events found</div>
                ) : (
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Event Type</th>
                                    <th>IP Address</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {logs.map(log => {
                                    const user = users.find(u => u.id === log.user_id);
                                    return (
                                        <tr key={log.id}>
                                            <td>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    {getEventIcon(log.event_type)}
                                                    <span>{new Date(ensureUTC(log.timestamp)).toLocaleString()}</span>
                                                </div>
                                            </td>
                                            <td>{user ? (user.full_name || user.username) : `User #${log.user_id}`}</td>
                                            <td>
                                                <span className={`${getEventBadgeClass(log.event_type)} ${log.event_type === 'failed_login' ? 'login-error-highlight' : ''}`}>
                                                    {log.event_type.replace('_', ' ').toUpperCase()}
                                                </span>
                                            </td>
                                            <td>{log.ip_address || 'N/A'}</td>
                                            <td>
                                                <small style={{ color: 'var(--text-secondary)' }}>
                                                    {JSON.stringify(log.details)}
                                                </small>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Recent Failed Logins */}
            {stats && stats.recent_failed_logins && stats.recent_failed_logins.length > 0 && (
                <div className="card full-width">
                    <h3><AlertTriangle size={20} className="text-red" /> Recent Failed Login Attempts</h3>
                    <ul className="timeline-list">
                        {stats.recent_failed_logins.map((attempt, idx) => {
                            const user = users.find(u => u.id === attempt.user_id);
                            return (
                                <li key={idx}>
                                    <span className="time">{new Date(ensureUTC(attempt.timestamp)).toLocaleString()}</span>
                                    <span className="error-badge">FAILED</span>
                                    User: {user ? (user.full_name || user.username) : `#${attempt.user_id}`}
                                    {attempt.ip_address && ` | IP: ${attempt.ip_address}`}
                                </li>
                            );
                        })}
                    </ul>
                </div>
            )}
        </div>
    );
};

export default Forensics;
