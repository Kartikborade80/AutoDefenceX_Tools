import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../api';
import { Users, Clock, Calendar, MessageSquare, UserX, Power, LogOut, CheckCircle, AlertCircle, Printer, Terminal } from 'lucide-react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import './Dashboard.css';

const Monitoring = () => {
    const navigate = useNavigate();
    const [departments, setDepartments] = useState([]);
    const [employees, setEmployees] = useState([]);
    const [selectedEmployee, setSelectedEmployee] = useState('');
    const [selectedDate, setSelectedDate] = useState(new Date().toISOString().split('T')[0]);
    const [activityLogs, setActivityLogs] = useState([]);
    const [staffSummary, setStaffSummary] = useState([]);
    const [loading, setLoading] = useState(true);
    const [currentUser, setCurrentUser] = useState(null);

    useEffect(() => {
        const loadInitialData = async () => {
            try {
                const token = localStorage.getItem('token');
                const user = JSON.parse(localStorage.getItem('user_info'));
                setCurrentUser(user);

                const resDepts = await axios.get('/departments/', { headers: { Authorization: `Bearer ${token}` } });
                setDepartments(resDepts.data);

                const resUsers = await axios.get('/users/', {
                    headers: { Authorization: `Bearer ${token}` }
                });

                if (user.role === 'Admin' || user.role === 'admin') {
                    // Admin sees everyone
                    setEmployees(resUsers.data);
                } else {
                    // HOD View
                    const myDept = resDepts.data.find(d => d.hod_id === user.id);
                    if (myDept && myDept.monitoring_enabled) {
                        const myStaff = resUsers.data.filter(u => u.department_id === myDept.id);
                        setEmployees(myStaff);
                    } else {
                        setEmployees([]);
                    }
                }

            } catch (err) {
                console.error("Failed to load monitoring data", err);
            } finally {
                setLoading(false);
            }
        };
        loadInitialData();
    }, []);

    useEffect(() => {
        if (selectedEmployee) {
            fetchEmployeeDetails(selectedEmployee);
        }
    }, [selectedEmployee, selectedDate]);

    const fetchEmployeeDetails = async (userId) => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get(`/users/${userId}/activity`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            const sorted = res.data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            // Filter logs by selected date
            const filtered = sorted.filter(log => {
                const logDate = new Date(ensureUTC(log.timestamp)).toISOString().split('T')[0];
                return logDate === selectedDate;
            });
            setActivityLogs(filtered);
        } catch (err) {
            console.error("Failed to fetch employee activity", err);
        }
    };

    const ensureUTC = (ts) => {
        if (!ts.endsWith('Z') && !ts.includes('+')) return ts + 'Z';
        return ts;
    };

    const calculateDutyTime = (logs) => {
        let totalMs = 0;
        let loginTime = null;

        const sortedLogs = [...logs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        sortedLogs.forEach(log => {
            if (log.action === 'login') {
                loginTime = new Date(ensureUTC(log.timestamp));
            } else if (log.action === 'logout' && loginTime) {
                totalMs += (new Date(ensureUTC(log.timestamp)) - loginTime);
                loginTime = null;
            }
        });

        if (loginTime) {
            totalMs += (new Date() - loginTime);
        }

        const hours = Math.floor(totalMs / 3600000);
        const minutes = Math.floor((totalMs % 3600000) / 60000);
        return { hours, minutes, totalMs };
    };

    const handlePrint = () => {
        const doc = new jsPDF();
        doc.setFontSize(20);
        doc.text('Employee Monitoring Report', 14, 22);
        doc.setFontSize(11);
        doc.setTextColor(100);

        const empName = employees.find(e => e.id === parseInt(selectedEmployee))?.full_name || 'All Staff';
        doc.text(`Employee: ${empName}`, 14, 30);
        doc.text(`Date: ${selectedDate}`, 14, 35);

        const tableColumn = ["Action", "Timestamp", "Details"];
        const tableRows = activityLogs.map(log => [
            log.action.toUpperCase(),
            new Date(ensureUTC(log.timestamp)).toLocaleString(),
            log.details?.ip || 'N/A'
        ]);

        autoTable(doc, {
            head: [tableColumn],
            body: tableRows,
            startY: 45,
        });

        doc.save(`monitoring_${empName}_${selectedDate}.pdf`);
    };

    const handleAction = async (action, rawUserId) => {
        const userId = parseInt(rawUserId);
        try {
            if (action === 'Logout' || action === 'Stop') {
                const token = localStorage.getItem('token');
                const res = await axios.get('/endpoints/', { headers: { Authorization: `Bearer ${token}` } });
                const session = res.data.find(e => parseInt(e.user_id) === userId);

                if (session) {
                    if (window.confirm(`Are you sure you want to ${action} session for ${session.full_name}?`)) {
                        await axios.post(`/endpoints/${session.endpoint_id}/${action.toLowerCase()}`, {}, {
                            headers: { Authorization: `Bearer ${token}` }
                        });
                        alert(`${action} command sent successfully.`);
                        fetchEmployeeDetails(userId);
                    }
                } else {
                    alert(`No active live session found for this user. They may be offline.`);
                }
            } else if (action === 'Message') {
                navigate('/messages', { state: { openChatWith: userId } });
            } else if (action === 'Explore') {
                const token = localStorage.getItem('token');
                const res = await axios.get('/endpoints/', { headers: { Authorization: `Bearer ${token}` } });
                const session = res.data.find(e => parseInt(e.user_id) === userId);
                if (session) {
                    navigate(`/endpoints/${session.endpoint_id}`);
                } else {
                    alert("This user does not have an active endpoint session to inspect.");
                }
            } else {
                alert(`${action} action initiated.`);
            }
        } catch (err) {
            console.error("Action failed:", err);
            alert(`Failed to perform ${action}: ${err.message}`);
        }
    };

    const renderContent = () => {
        if (!selectedEmployee) {
            return (
                <div className="card full-width">
                    <h3>Department Productivity Summary</h3>
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Employee</th>
                                    <th>Job Title</th>
                                    <th>Status</th>
                                    <th>Active Time</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {employees.map(e => (
                                    <tr key={e.id}>
                                        <td>
                                            <div style={{ fontWeight: '600' }}>{e.full_name || e.username}</div>
                                            <div className="text-muted" style={{ fontSize: '0.75rem' }}>{e.employee_id}</div>
                                        </td>
                                        <td>{e.job_title || 'N/A'}</td>
                                        <td>
                                            <span className={`badge ${e.last_login ? 'badge-success' : 'badge-user'}`}>
                                                {e.last_login ? 'ONLINE' : 'OFFLINE'}
                                            </span>
                                        </td>
                                        <td className="mono text-white">
                                            {e.last_login ? 'Active Now' : '0h 0m'}
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: '8px' }}>
                                                <button className="btn-modern-primary btn-modern-sm" title="Inspect" onClick={() => handleAction('Explore', e.id)}>
                                                    <Terminal size={14} />
                                                </button>
                                                <button className="btn-modern-primary btn-modern-sm" title="Message" onClick={() => handleAction('Message', e.id)}>
                                                    <MessageSquare size={14} />
                                                </button>
                                                <button className="btn-modern-warning btn-modern-sm" title="Logout" onClick={() => handleAction('Logout', e.id)}>
                                                    <LogOut size={14} />
                                                </button>
                                                <button className="btn-modern-danger btn-modern-sm" title="Kill" onClick={() => handleAction('Stop', e.id)}>
                                                    <Power size={14} />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            );
        }

        const currentEmployee = employees.find(e => e.id === parseInt(selectedEmployee));
        const duty = calculateDutyTime(activityLogs);
        const isShortDuty = duty.totalMs > 0 && duty.totalMs < (8 * 3600000);

        return (
            <div className="employee-monitoring-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '25px' }}>
                <div className="card">
                    <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                            <h3>Productivity Metrics</h3>
                            {currentEmployee?.last_login && (
                                <span className="badge badge-success" style={{ height: '24px', fontSize: '0.7rem' }}>
                                    <span className="live-dot"></span> LIVE
                                </span>
                            )}
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <Printer size={18} className="text-blue cursor-pointer" onClick={handlePrint} />
                            <Calendar size={18} className="text-blue" />
                        </div>
                    </div>

                    {currentEmployee && (
                        <div className="profile-mini-card" style={{
                            display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '20px', padding: '12px',
                            background: 'rgba(255,255,255,0.03)', borderRadius: '10px', border: '1px solid var(--border-glass)'
                        }}>
                            <div style={{
                                width: '45px', height: '45px', background: 'var(--primary)', borderRadius: '50%',
                                display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 'bold'
                            }}>
                                {(currentEmployee.full_name || 'U').charAt(0)}
                            </div>
                            <div>
                                <div style={{ fontWeight: '700' }}>{currentEmployee.full_name}</div>
                                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{currentEmployee.job_title}</div>
                            </div>
                        </div>
                    )}

                    <div style={{
                        padding: '20px', textAlign: 'center', borderRadius: '12px', marginBottom: '20px',
                        background: isShortDuty ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                        border: isShortDuty ? '1px solid #ef4444' : '1px solid #10b981'
                    }}>
                        <div style={{ fontSize: '0.8rem', opacity: 0.7 }}>TOTAL DUTY TIME</div>
                        <div style={{ fontSize: '2.2rem', fontWeight: '800', color: isShortDuty ? '#ef4444' : '#10b981' }}>
                            {duty.hours}h {duty.minutes}m
                        </div>
                        {isShortDuty && <div style={{ fontSize: '0.7rem', color: '#ef4444', marginTop: '5px' }}>SHORT DUTY DETECTED</div>}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        <button className="btn-modern-primary" style={{ width: '100%' }} onClick={() => handleAction('Message', selectedEmployee)}>MESSAGE USER</button>
                        <button className="btn-modern-warning" style={{ width: '100%' }} onClick={() => handleAction('Logout', selectedEmployee)}>LOGOUT AGENT</button>
                        <button className="btn-modern-danger" style={{ width: '100%' }} onClick={() => handleAction('Stop', selectedEmployee)}>KILL ACCESS</button>
                    </div>
                </div>

                <div className="card">
                    <h3>Session Activity Log</h3>
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Action</th>
                                    <th>Time</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {activityLogs.length === 0 ? (
                                    <tr><td colSpan="3" style={{ textAlign: 'center', padding: '20px' }}>No records for this date</td></tr>
                                ) : (
                                    activityLogs.map(log => (
                                        <tr key={log.id}>
                                            <td style={{ fontWeight: 'bold' }}>{log.action.toUpperCase()}</td>
                                            <td>{new Date(ensureUTC(log.timestamp)).toLocaleTimeString()}</td>
                                            <td>{log.details?.ip || '127.0.0.1'}</td>
                                        </tr>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        );
    };

    if (loading) return <div className="loading">Loading Monitoring Data...</div>;

    return (
        <div className="dashboard-container fade-in">
            <header className="page-header">
                <div>
                    <h2><Users className="icon-lg" /> Monitoring Hub</h2>
                    <p className="subtitle">Departmental Oversight Center</p>
                </div>
                <div className="badge pulse red">SECURE AREA</div>
            </header>

            <div className="card full-width" style={{ padding: '15px', marginBottom: '20px' }}>
                <div style={{ display: 'flex', gap: '15px' }}>
                    <div style={{ flex: 1 }}>
                        <label className="label-sm">Select User</label>
                        <select className="form-input" value={selectedEmployee} onChange={(e) => setSelectedEmployee(e.target.value)}>
                            <option value="">Summary View</option>
                            {employees.map(e => <option key={e.id} value={e.id}>{e.full_name}</option>)}
                        </select>
                    </div>
                    <div style={{ flex: 1 }}>
                        <label className="label-sm">Date</label>
                        <input className="form-input" type="date" value={selectedDate} onChange={(e) => setSelectedDate(e.target.value)} />
                    </div>
                </div>
            </div>

            {renderContent()}
        </div>
    );
};

export default Monitoring;
