import React, { useState, useEffect } from 'react';
import api from '../api';
import { Calendar, Clock, Download, Filter } from 'lucide-react';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import * as XLSX from 'xlsx';

/**
 * Attendance Component
 * Handles personal and departmental attendance tracking with professional PDF export.
 */
const Attendance = () => {
    const [attendance, setAttendance] = useState([]);
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [isExportModalOpen, setIsExportModalOpen] = useState(false);
    const [isFormatModalOpen, setIsFormatModalOpen] = useState(false);
    const [exportSettings, setExportSettings] = useState({
        status: 'all',
        date: '',
        employeeId: 'all',
        selectedIds: []
    });
    const [currentTime, setCurrentTime] = useState(new Date());
    const [filterText, setFilterText] = useState('');
    const [filterStatus, setFilterStatus] = useState('all');
    const [filterDate, setFilterDate] = useState('');
    const [filterTimeStart, setFilterTimeStart] = useState('');
    const [filterTimeEnd, setFilterTimeEnd] = useState('');
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');

    const ensureUTC = (timestamp) => {
        if (!timestamp) return '';
        return timestamp.endsWith('Z') ? timestamp : timestamp + 'Z';
    };

    // Live Clock Timer
    useEffect(() => {
        const timer = setInterval(() => {
            setCurrentTime(new Date());
        }, 1000); // Update every second for live duration
        return () => clearInterval(timer);
    }, []);

    // Load Initial Data
    useEffect(() => {
        const fetchData = async () => {
            try {
                if (!userInfo.id) {
                    setLoading(false);
                    return;
                }

                // 1. Fetch Users (for mapping IDs to Names)
                const usersResponse = await api.get('/users/');
                if (Array.isArray(usersResponse.data)) {
                    setUsers(usersResponse.data);
                } else {
                    console.warn("Attendance: Expected users array but received:", usersResponse.data);
                    setUsers([]);
                }

                // 2. Fetch Attendance
                let endpoint = `/attendance/${userInfo.id}`;
                if (userInfo.is_department_head && userInfo.department_id) {
                    endpoint = `/attendance/department/${userInfo.department_id}`;
                }

                const response = await api.get(endpoint);
                const rawData = Array.isArray(response.data) ? response.data : [];
                const sortedData = rawData.sort((a, b) => new Date(ensureUTC(b.login_time)) - new Date(ensureUTC(a.login_time)));
                setAttendance(sortedData);

                // Initialize selection for export
                setExportSettings(prev => ({ ...prev, selectedIds: sortedData.map(r => r.id) }));
            } catch (error) {
                console.error("Attendance: Data Fetch Error", error);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [userInfo.id, userInfo.is_department_head, userInfo.department_id]);

    const getUserName = (userId) => {
        if (!Array.isArray(users)) return `User #${userId}`;
        const user = users.find(u => u.id === userId);
        return user ? (user.full_name || user.username) : `User #${userId}`;
    };

    /**
     * Enhanced PDF Export with Selection & Names
     */
    const handleExportPDF = (dataToExport = attendance) => {
        try {
            const doc = new jsPDF();
            const generationDate = new Date().toLocaleString();
            const employeeName = userInfo.full_name || userInfo.username || "Employee";
            const companyName = userInfo.company_name || localStorage.getItem('company_name') || "AutoDefenceX Network";

            // Header Section (Same as before but with minor fixes)
            doc.setFillColor(0, 123, 255);
            doc.rect(0, 0, 210, 40, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(22);
            doc.setFont("helvetica", "bold");
            doc.text('ATTENDANCE REPORT', 14, 25);
            doc.setFontSize(10);
            doc.setFont("helvetica", "normal");
            doc.text('SECURE ENTERPRISE NETWORK ACCESS LOG', 14, 32);

            // Metadata
            doc.setTextColor(50, 50, 50);
            doc.setFontSize(10);
            doc.text('REPORT METADATA:', 14, 52);
            doc.line(14, 54, 196, 54);
            doc.setFontSize(11);
            const metadataY = 64;
            doc.text(`Exported By: ${employeeName}`, 14, metadataY);
            doc.text(`Organization: ${companyName}`, 14, metadataY + 8);
            doc.text(`Generated On: ${generationDate}`, 14, metadataY + 16);

            // Table
            const tableColumn = [
                "Employee Name", "Date", "Login Time", "Logout Time", "Working Hours", "Status"
            ];

            const tableRows = dataToExport.map(record => [
                getUserName(record.user_id),
                new Date(ensureUTC(record.login_time)).toLocaleDateString(),
                new Date(ensureUTC(record.login_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                record.logout_time ? new Date(ensureUTC(record.logout_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "Active Now",
                `${(record.working_hours || 0).toFixed(2)} hrs`,
                (record.status || 'present').toUpperCase()
            ]);

            autoTable(doc, {
                head: [tableColumn],
                body: tableRows,
                startY: 95,
                theme: 'grid',
                headStyles: { fillColor: [0, 123, 255], textColor: 255 },
                styles: { fontSize: 9 }
            });

            const fileName = `Report_${new Date().toISOString().split('T')[0]}.pdf`;
            doc.save(fileName);
        } catch (error) {
            console.error("PDF Export Error:", error);
            alert(`Failed to export PDF: ${error.message}`);
        }
    };

    /**
     * Professional Excel Export
     */
    const handleExportExcel = (dataToExport = attendance) => {
        try {
            if (!XLSX) {
                alert("Excel library not loaded. Please try again.");
                return;
            }
            const workData = dataToExport.map(record => ({
                "Employee Name": getUserName(record.user_id),
                "Date": new Date(ensureUTC(record.login_time)).toLocaleDateString(),
                "Login Time": new Date(ensureUTC(record.login_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                "Logout Time": record.logout_time ? new Date(ensureUTC(record.logout_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "Active Now",
                "Working Hours": (record.working_hours || 0).toFixed(2),
                "Status": (record.status || 'present').toUpperCase()
            }));

            const worksheet = XLSX.utils.json_to_sheet(workData);
            const workbook = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(workbook, worksheet, "Attendance Logs");

            const fileName = `Attendance_Report_${new Date().toISOString().split('T')[0]}.xlsx`;
            XLSX.writeFile(workbook, fileName);
        } catch (error) {
            console.error("Excel Export Error:", error);
            alert("Failed to export Excel. Please try again.");
        }
    };

    return (
        <div className="attendance-container slide-up">
            {/* Header Area */}
            <header className="page-header">
                <div className="header-title-area">
                    <h2><Calendar size={28} /> My Attendance</h2>
                    <p className="text-muted">Security-audited daily login and logout logs.</p>
                </div>
                <div className="header-actions">
                    <button className="premium-export-btn" onClick={() => setIsExportModalOpen(true)}>
                        <Download size={20} />
                        <span>Export PDF Report</span>
                    </button>
                </div>
            </header>

            {/* Current Status Banner */}
            <div className="current-status-banner mb-lg">
                {attendance.length > 0 && attendance[0] && !attendance[0].logout_time ? (
                    <div className="card status-card-active">
                        <div className="status-indicator">
                            <div className="status-dot pulsing-dot"></div>
                            <div className="status-content">
                                <h3 className="status-title">🟢 ON DUTY</h3>
                                <p className="status-subtitle">Your session is actively being tracked</p>
                            </div>
                        </div>
                        <div className="status-details">
                            <div className="detail-item">
                                <span className="detail-label">Login Time</span>
                                <span className="detail-value">
                                    {new Date(ensureUTC(attendance[0].login_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </span>
                            </div>
                            <div className="detail-item">
                                <span className="detail-label">Live Duration</span>
                                <span className="detail-value live-duration">
                                    {(() => {
                                        const login = new Date(ensureUTC(attendance[0].login_time)).getTime();
                                        const duration = (currentTime.getTime() - login) / (1000 * 60 * 60);
                                        return `${duration.toFixed(2)} hrs`;
                                    })()}
                                </span>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="card status-card-offline">
                        <div className="status-indicator">
                            <div className="status-dot offline-dot"></div>
                            <div className="status-content">
                                <h3 className="status-title">⚫ OFFLINE</h3>
                                <p className="status-subtitle">No active session detected</p>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Statistics Row */}
            <div className="attendance-stats-row mb-lg">
                <div className="card stat-card">
                    <div className="stat-icon info-lite"><Clock size={24} /></div>
                    <div className="stat-content">
                        <span className="stat-label">Total Days Active</span>
                        <span className="stat-value">{attendance.length}</span>
                    </div>
                </div>
                <div className="card stat-card">
                    <div className="stat-icon success-lite"><Calendar size={24} /></div>
                    <div className="stat-content">
                        <span className="stat-label">Productive Hours</span>
                        <span className="stat-value">
                            {attendance.reduce((acc, curr) => acc + (curr.working_hours || 0), 0).toFixed(1)} hrs
                        </span>
                    </div>
                </div>
            </div>

            {/* Statistics Row */}

            {/* Attendance Logs Table */}
            <div className="card table-card-modern">
                <div className="card-header-styled">
                    <h3 className="section-title">
                        <Filter size={18} /> Verified Logs
                        <span style={{ fontSize: '0.8rem', marginLeft: '15px', fontWeight: 'normal', color: '#94a3b8' }}>
                            Live: {currentTime.toLocaleDateString()} {currentTime.toLocaleTimeString()}
                        </span>
                    </h3>
                </div>
                {loading ? (
                    <div className="loading-state-p">
                        <p>Loading encrypted log records...</p>
                    </div>
                ) : !userInfo.id ? (
                    <div className="loading-state-p" style={{ color: '#f59e0b', padding: '40px' }}>
                        <p style={{ fontSize: '1.1rem', marginBottom: '10px' }}>⚠️ Session Data Missing</p>
                        <p style={{ fontSize: '0.9rem', color: '#94a3b8' }}>
                            Please logout and login again to refresh your session data.
                        </p>
                    </div>
                ) : (
                    <div className="table-wrapper">
                        <div className="advanced-filter-bar" style={{
                            padding: '16px 24px',
                            background: 'rgba(255,255,255,0.02)',
                            borderBottom: '1px solid var(--border-color)',
                            display: 'flex',
                            alignItems: 'flex-end',
                            gap: '15px',
                            flexWrap: 'nowrap',
                            overflowX: 'auto',
                            scrollbarWidth: 'none'
                        }}>
                            <div className="filter-group">
                                <label style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '5px', display: 'block' }}>Search</label>
                                <div style={{ position: 'relative' }}>
                                    <input
                                        type="text"
                                        placeholder="Search logs..."
                                        className="cyber-input"
                                        style={{ padding: '8px 12px 8px 35px', borderRadius: '8px', fontSize: '0.85rem', width: '200px' }}
                                        value={filterText}
                                        onChange={(e) => setFilterText(e.target.value)}
                                    />
                                    <Filter size={14} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                                </div>
                            </div>

                            <div className="filter-group">
                                <label style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '5px', display: 'block' }}>Status</label>
                                <select
                                    className="cyber-input"
                                    style={{ padding: '8px 12px', borderRadius: '8px', fontSize: '0.85rem', width: '160px' }}
                                    value={filterStatus}
                                    onChange={(e) => setFilterStatus(e.target.value)}
                                >
                                    <option value="all">All Statuses</option>
                                    <option value="present">Present</option>
                                    <option value="absent">Absent</option>
                                    <option value="emergency_leave">Emergency Leave</option>
                                    <option value="on_duty">On Duty</option>
                                </select>
                            </div>

                            <div className="filter-group">
                                <label style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '5px', display: 'block' }}>Date</label>
                                <input
                                    type="date"
                                    className="cyber-input"
                                    style={{ padding: '7px 12px', borderRadius: '8px', fontSize: '0.85rem' }}
                                    value={filterDate}
                                    onChange={(e) => setFilterDate(e.target.value)}
                                />
                            </div>

                            <div className="filter-group">
                                <label style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '5px', display: 'block' }}>Time Range</label>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <input
                                        type="time"
                                        className="cyber-input"
                                        style={{ padding: '7px 8px', borderRadius: '8px', fontSize: '0.85rem' }}
                                        value={filterTimeStart}
                                        onChange={(e) => setFilterTimeStart(e.target.value)}
                                    />
                                    <span style={{ color: '#64748b' }}>-</span>
                                    <input
                                        type="time"
                                        className="cyber-input"
                                        style={{ padding: '7px 8px', borderRadius: '8px', fontSize: '0.85rem' }}
                                        value={filterTimeEnd}
                                        onChange={(e) => setFilterTimeEnd(e.target.value)}
                                    />
                                </div>
                            </div>

                            <button
                                className="btn-modern-secondary"
                                style={{
                                    padding: '0 15px',
                                    borderRadius: '8px',
                                    fontSize: '0.85rem',
                                    height: '38px',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'center',
                                    whiteSpace: 'nowrap',
                                    border: '1px solid var(--border-color)',
                                    background: 'rgba(255,255,255,0.05)',
                                    cursor: 'pointer'
                                }}
                                onClick={() => {
                                    setFilterText('');
                                    setFilterStatus('all');
                                    setFilterDate('');
                                    setFilterTimeStart('');
                                    setFilterTimeEnd('');
                                }}
                            >
                                Reset Filters
                            </button>
                        </div>
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    {userInfo.is_department_head && <th>Employee Name</th>}
                                    <th>Date</th>
                                    <th>Login</th>
                                    <th>Logout</th>
                                    <th>Device / OS</th>
                                    <th>Duration</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {attendance.length > 0 ? (
                                    attendance
                                        .filter(record => {
                                            // 1. Text Search
                                            const searchStr = `${new Date(ensureUTC(record.login_time)).toLocaleDateString()} ${record.status} ${record.browser_name} ${record.os_name} ${record.user_id}`.toLowerCase();
                                            const matchesText = searchStr.includes(filterText.toLowerCase());

                                            // 2. Status Filter
                                            const matchesStatus = filterStatus === 'all' || record.status === filterStatus;

                                            // 3. Date Filter
                                            const recDate = new Date(ensureUTC(record.login_time)).toISOString().split('T')[0];
                                            const matchesDate = !filterDate || recDate === filterDate;

                                            // 4. Time Range Filter (based on login_time)
                                            const recTime = new Date(ensureUTC(record.login_time)).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
                                            const matchesTimeStart = !filterTimeStart || recTime >= filterTimeStart;
                                            const matchesTimeEnd = !filterTimeEnd || recTime <= filterTimeEnd;

                                            return matchesText && matchesStatus && matchesDate && matchesTimeStart && matchesTimeEnd;
                                        })
                                        .map((record) => {
                                            let duration = record.working_hours || 0;
                                            if (!record.logout_time) {
                                                const login = new Date(ensureUTC(record.login_time)).getTime();
                                                // Use currentTime state for live updates
                                                duration = (currentTime.getTime() - login) / (1000 * 60 * 60);
                                            }

                                            return (
                                                <tr key={record.id}>
                                                    {userInfo.is_department_head && <td className="text-white font-semibold">{getUserName(record.user_id)}</td>}
                                                    <td className="font-semibold">{new Date(ensureUTC(record.login_time)).toLocaleDateString()}</td>
                                                    <td>{new Date(ensureUTC(record.login_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
                                                    <td>
                                                        {record.logout_time
                                                            ? new Date(ensureUTC(record.logout_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                                                            : <span className="text-green pulse">ON-DUTY</span>
                                                        }
                                                    </td>
                                                    <td>
                                                        <div className="device-info-cell">
                                                            <span className="browser-label">{record.browser_name || 'Unknown'}</span>
                                                            <span className="os-label">{record.os_name || 'Unknown'}</span>
                                                        </div>
                                                    </td>
                                                    <td className="text-info font-medium">
                                                        {duration.toFixed(2)} hrs
                                                        {!record.logout_time && <span className="text-xs text-muted"> (Live)</span>}
                                                    </td>
                                                    <td>
                                                        <span className={`badge ${record.status === 'present' ? 'badge-success' : 'badge-danger'}`}>
                                                            {record.status}
                                                        </span>
                                                    </td>
                                                </tr>
                                            );
                                        })
                                ) : (
                                    <tr>
                                        <td colSpan="6" className="no-data-cell">
                                            No verified attendance records found.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Premium Styles */}
            {/* Export Modal Overlay */}
            {isExportModalOpen && (
                <div className="modal-overlay" style={{
                    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                    backgroundColor: 'rgba(0,0,0,0.8)', zIndex: 1000,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backdropFilter: 'blur(8px)'
                }}>
                    <div className="modal-content card slide-up" style={{
                        width: '90%', maxWidth: '1000px', maxHeight: '90vh',
                        padding: '30px', display: 'flex', flexDirection: 'column', gap: '25px',
                        position: 'relative', overflow: 'hidden'
                    }}>
                        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <h2 style={{ fontSize: '1.5rem', margin: 0 }}>Configure Export Report</h2>
                            <button onClick={() => setIsExportModalOpen(false)} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1.5rem' }}>×</button>
                        </header>

                        <div className="modal-filters" style={{
                            display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px',
                            background: 'rgba(255,255,255,0.03)', padding: '20px', borderRadius: '12px'
                        }}>
                            <div className="filter-group">
                                <label style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '8px', display: 'block' }}>Report Type / Status</label>
                                <select
                                    className="cyber-input" style={{ width: '100%' }}
                                    value={exportSettings.status}
                                    onChange={(e) => setExportSettings(prev => ({ ...prev, status: e.target.value }))}
                                >
                                    <option value="all">All Logs</option>
                                    <option value="present">Present Only</option>
                                    <option value="absent">Absent Only</option>
                                    <option value="emergency_leave">Emergency Leave</option>
                                </select>
                            </div>

                            <div className="filter-group">
                                <label style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '8px', display: 'block' }}>Filter by Date</label>
                                <input
                                    type="date" className="cyber-input" style={{ width: '100%' }}
                                    value={exportSettings.date}
                                    onChange={(e) => setExportSettings(prev => ({ ...prev, date: e.target.value }))}
                                />
                            </div>

                            {userInfo.is_department_head && (
                                <div className="filter-group">
                                    <label style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '8px', display: 'block' }}>Select Employee</label>
                                    <select
                                        className="cyber-input" style={{ width: '100%' }}
                                        value={exportSettings.employeeId}
                                        onChange={(e) => setExportSettings(prev => ({ ...prev, employeeId: e.target.value }))}
                                    >
                                        <option value="all">Every Staff Member</option>
                                        {users.filter(u => u.department_id === userInfo.department_id).map(user => (
                                            <option key={user.id} value={user.id}>{user.full_name || user.username}</option>
                                        ))}
                                    </select>
                                </div>
                            )}
                        </div>

                        <div className="preview-section" style={{ flex: 1, overflowY: 'auto', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }}>
                            <div style={{ padding: '15px', borderBottom: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.02)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <h3 style={{ fontSize: '1rem', margin: 0 }}>Report Data Preview</h3>
                                <span style={{ fontSize: '0.8rem', color: '#3b82f6' }}>Showing matching records</span>
                            </div>
                            <table className="table-unified" style={{ fontSize: '0.85rem' }}>
                                <thead>
                                    <tr>
                                        <th style={{ width: '40px' }}><input type="checkbox"
                                            checked={exportSettings.selectedIds.length > 0 && attendance.filter(r => {
                                                const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                                const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                                const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                                return sMatch && dMatch && eMatch;
                                            }).every(r => exportSettings.selectedIds.includes(r.id))}
                                            onChange={(e) => {
                                                const filtered = attendance.filter(r => {
                                                    const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                                    const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                                    const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                                    return sMatch && dMatch && eMatch;
                                                });

                                                if (e.target.checked) {
                                                    // Add all filtered but not yet selected
                                                    const newIds = [...new Set([...exportSettings.selectedIds, ...filtered.map(r => r.id)])];
                                                    setExportSettings(prev => ({ ...prev, selectedIds: newIds }));
                                                } else {
                                                    // Remove filtered from selected
                                                    const filteredIds = filtered.map(r => r.id);
                                                    setExportSettings(prev => ({ ...prev, selectedIds: prev.selectedIds.filter(id => !filteredIds.includes(id)) }));
                                                }
                                            }}
                                        /></th>
                                        <th>Employee</th>
                                        <th>Date</th>
                                        <th>Login</th>
                                        <th>Duration</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {attendance
                                        .filter(r => {
                                            const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                            const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                            const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                            return sMatch && dMatch && eMatch;
                                        })
                                        .map(r => (
                                            <tr key={r.id}>
                                                <td><input type="checkbox" checked={exportSettings.selectedIds.includes(r.id)} onChange={(e) => {
                                                    setExportSettings(prev => ({
                                                        ...prev,
                                                        selectedIds: e.target.checked ? [...prev.selectedIds, r.id] : prev.selectedIds.filter(id => id !== r.id)
                                                    }));
                                                }} /></td>
                                                <td>{getUserName(r.user_id)}</td>
                                                <td>{new Date(ensureUTC(r.login_time)).toLocaleDateString()}</td>
                                                <td>{new Date(ensureUTC(r.login_time)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td>
                                                <td>{(r.working_hours || 0).toFixed(2)}h</td>
                                                <td><span className={`badge ${r.status === 'present' ? 'badge-success' : 'badge-danger'}`} style={{ transform: 'scale(0.8)' }}>{r.status}</span></td>
                                            </tr>
                                        ))
                                    }
                                </tbody>
                            </table>
                        </div>

                        <footer style={{ display: 'flex', justifyContent: 'flex-end', gap: '15px' }}>
                            <button className="cyber-input" onClick={() => setIsExportModalOpen(false)} style={{ padding: '10px 25px' }}>Cancel</button>
                            <button className="premium-export-btn" onClick={() => {
                                const filteredCount = attendance.filter(r => {
                                    const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                    const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                    const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                    return sMatch && dMatch && eMatch && exportSettings.selectedIds.includes(r.id);
                                }).length;

                                if (filteredCount === 0) {
                                    alert("No records match your filters and selection.");
                                    return;
                                }
                                setIsFormatModalOpen(true);
                            }}>
                                <Download size={18} /> Download Filtered & Selected ({
                                    attendance.filter(r => {
                                        const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                        const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                        const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                        return sMatch && dMatch && eMatch && exportSettings.selectedIds.includes(r.id);
                                    }).length
                                })
                            </button>
                        </footer>
                    </div>
                </div>
            )}

            {/* Format Selection Modal */}
            {isFormatModalOpen && (
                <div className="modal-overlay" style={{
                    position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
                    backgroundColor: 'rgba(0,0,0,0.5)', zIndex: 1100,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    backdropFilter: 'blur(4px)'
                }}>
                    <div className="modal-content card slide-up" style={{
                        width: '320px', padding: '25px', display: 'flex', flexDirection: 'column', gap: '20px',
                        textAlign: 'center'
                    }}>
                        <h3 style={{ margin: 0, fontSize: '1.2rem' }}>Choose Export Format</h3>
                        <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
                            Selected {exportSettings.selectedIds.length} records
                        </p>

                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                            <button
                                className="btn-modern-primary"
                                style={{ width: '100%', padding: '12px', borderRadius: '8px' }}
                                onClick={() => {
                                    const finalData = attendance.filter(r => {
                                        const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                        const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                        const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                        return sMatch && dMatch && eMatch && exportSettings.selectedIds.includes(r.id);
                                    });
                                    handleExportPDF(finalData);
                                    setIsFormatModalOpen(false);
                                    setIsExportModalOpen(false);
                                }}
                            >
                                📄 Export as PDF
                            </button>
                            <button
                                className="btn-modern-secondary"
                                style={{ width: '100%', padding: '12px', borderRadius: '8px', border: '1px solid #10b981', color: '#10b981' }}
                                onClick={() => {
                                    const finalData = attendance.filter(r => {
                                        const sMatch = exportSettings.status === 'all' || r.status === exportSettings.status;
                                        const dMatch = !exportSettings.date || new Date(ensureUTC(r.login_time)).toISOString().split('T')[0] === exportSettings.date;
                                        const eMatch = exportSettings.employeeId === 'all' || r.user_id === parseInt(exportSettings.employeeId);
                                        return sMatch && dMatch && eMatch && exportSettings.selectedIds.includes(r.id);
                                    });
                                    handleExportExcel(finalData);
                                    setIsFormatModalOpen(false);
                                    setIsExportModalOpen(false);
                                }}
                            >
                                📊 Export as Excel (.xlsx)
                            </button>
                        </div>

                        <button
                            className="cyber-input"
                            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
                            onClick={() => setIsFormatModalOpen(false)}
                        >
                            Back to configuration
                        </button>
                    </div>
                </div>
            )}

            <style>{`
                .premium-export-btn {
                    display: flex !important;
                    align-items: center !important;
                    gap: 12px !important;
                    padding: 12px 28px !important;
                    background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%) !important;
                    color: white !important;
                    border: 1px solid rgba(255, 255, 255, 0.1) !important;
                    border-radius: 14px !important;
                    font-weight: 700 !important;
                    font-size: 0.95rem !important;
                    cursor: pointer !important;
                    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
                    box-shadow: 0 4px 15px rgba(37, 99, 235, 0.25) !important;
                }

                .premium-export-btn:hover {
                    transform: translateY(-3px) scale(1.02) !important;
                    box-shadow: 0 10px 25px rgba(37, 99, 235, 0.4) !important;
                    background: linear-gradient(135deg, #60a5fa 0%, #2563eb 100%) !important;
                }

                .premium-export-btn:active {
                    transform: translateY(-1px) !important;
                }

                .info-lite { background: rgba(59, 130, 246, 0.08); color: #3b82f6; }
                .success-lite { background: rgba(16, 185, 129, 0.08); color: #10b981; }

                /* Consistency & Spacing */
                .attendance-stats-row {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                    gap: 20px;
                }
                .stat-card {
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    padding: 24px;
                }
                .stat-icon {
                    width: 52px;
                    height: 52px;
                    border-radius: 14px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .stat-content { display: flex; flex-direction: column; }
                .stat-label { font-size: 0.85rem; color: var(--text-muted); font-weight: 500; margin-bottom: 4px; }
                .stat-value { font-size: 1.6rem; font-weight: 800; color: var(--text-primary); }
                
                .table-card-modern { padding: 0; overflow: hidden; border-radius: 16px; border: 1px solid var(--border-color); }
                .card-header-styled { padding: 22px 24px; border-bottom: 1px solid var(--border-color); background: rgba(255, 255, 255, 0.01); }
                .section-title { font-size: 1.1rem; margin: 0; display: flex; align-items: center; gap: 12px; color: var(--text-primary); }
                .table-wrapper { overflow-x: auto; }
                .no-data-cell { text-align: center; padding: 60px !important; color: var(--text-muted); font-style: italic; }
                
                .font-semibold { font-weight: 600; }
                .font-medium { font-weight: 500; }
                .text-info { color: #3b82f6; }
                .loading-state-p { padding: 60px; text-align: center; color: var(--text-muted); font-weight: 500; }
                
                .pulse { animation: pulse-green 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
                @keyframes pulse-green {
                    0%, 100% { opacity: 1; }
                    50% { opacity: .5; }
                }

                /* Current Status Banner Styles */
                .current-status-banner { margin-bottom: 24px; }
                
                .status-card-active {
                    background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(5, 150, 105, 0.05) 100%);
                    border: 2px solid rgba(16, 185, 129, 0.3);
                    padding: 24px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    gap: 24px;
                }
                
                .status-card-offline {
                    background: rgba(100, 116, 139, 0.05);
                    border: 2px solid rgba(100, 116, 139, 0.2);
                    padding: 24px;
                }
                
                .status-indicator {
                    display: flex;
                    align-items: center;
                    gap: 16px;
                }
                
                .status-dot {
                    width: 16px;
                    height: 16px;
                    border-radius: 50%;
                    flex-shrink: 0;
                }
                
                .pulsing-dot {
                    background: #10b981;
                    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
                    animation: pulse-ring 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
                }
                
                .offline-dot {
                    background: #64748b;
                }
                
                @keyframes pulse-ring {
                    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
                    50% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
                    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
                }
                
                .status-content { flex: 1; }
                .status-title { 
                    font-size: 1.3rem; 
                    font-weight: 800; 
                    margin: 0; 
                    color: var(--text-primary);
                    margin-bottom: 4px;
                }
                .status-subtitle { 
                    font-size: 0.9rem; 
                    color: var(--text-muted); 
                    margin: 0;
                }
                
                .status-details {
                    display: flex;
                    gap: 32px;
                }
                
                .detail-item {
                    display: flex;
                    flex-direction: column;
                    align-items: flex-end;
                }
                
                .detail-label {
                    font-size: 0.75rem;
                    color: var(--text-muted);
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    margin-bottom: 4px;
                }
                
                .detail-value {
                    font-size: 1.3rem;
                    font-weight: 700;
                    color: var(--text-primary);
                }
                
                .live-duration {
                    color: #10b981;
                    animation: pulse-text 2s ease-in-out infinite;
                }
                
                @keyframes pulse-text {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.7; }
                }

                .device-info-cell {
                    display: flex;
                    flex-direction: column;
                    gap: 2px;
                }
                .browser-label {
                    font-size: 0.85rem;
                    font-weight: 600;
                    color: var(--text-primary);
                }
                .os-label {
                    font-size: 0.7rem;
                    color: var(--text-muted);
                    text-transform: uppercase;
                    letter-spacing: 0.3px;
                }
            `}</style>
        </div>
    );
};

export default Attendance;
