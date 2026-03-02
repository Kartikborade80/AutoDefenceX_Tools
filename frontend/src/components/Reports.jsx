import React, { useState, useEffect } from 'react';
import axios from '../api';
import { FileText, Download, Users, Bug, Shield, CheckCircle, Activity, Filter, FileDown } from 'lucide-react';
import * as jspdf from 'jspdf';
import autoTable from 'jspdf-autotable';

// Re-map jsPDF and autoTable for different bundle environments
const getJsPDF = () => {
    if (typeof jspdf === 'function') return jspdf;
    if (jspdf && typeof jspdf.jsPDF === 'function') return jspdf.jsPDF;
    if (jspdf && typeof jspdf.default === 'function') return jspdf.default;
    return null;
};

const getAutoTable = (doc) => {
    if (typeof autoTable === 'function') return autoTable;
    if (doc && typeof doc.autoTable === 'function') return doc.autoTable.bind(doc);
    return null;
};
import './Dashboard.css';

const Reports = () => {
    const [reportType, setReportType] = useState('all-employees');
    const [reportData, setReportData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [users, setUsers] = useState([]);
    const [selectedUserId, setSelectedUserId] = useState('');
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [generatedAt, setGeneratedAt] = useState(null);

    useEffect(() => {
        // Fetch users list for employee report
        fetchUsers();
    }, []);

    useEffect(() => {
        // Auto-fetch report when type changes (except employee which needs selection)
        if (reportType !== 'employee') {
            fetchReport();
        }
    }, [reportType]);

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

    const fetchReport = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            let endpoint = '';

            switch (reportType) {
                case 'employee':
                    if (!selectedUserId) return;
                    endpoint = `/reports/employee/${selectedUserId}`;
                    break;
                case 'my-activity':
                    // Self report
                    const myId = JSON.parse(localStorage.getItem('user_info') || '{}').id;
                    if (!myId) return;
                    endpoint = `/reports/employee/${myId}`;
                    break;
                case 'all-employees':
                    endpoint = '/reports/all-employees';
                    break;
                case 'bugs':
                    endpoint = '/reports/bugs';
                    break;
                case 'security':
                    endpoint = '/reports/security';
                    break;

                case 'system-health':
                    endpoint = '/reports/system-health';
                    break;
                default:
                    return;
            }

            const queryParams = new URLSearchParams();
            if (startDate) queryParams.append('start_date', startDate);
            if (endDate) queryParams.append('end_date', endDate);

            const res = await axios.get(`${endpoint}?${queryParams.toString()}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setReportData(res.data);
            setGeneratedAt(new Date().toLocaleString());
        } catch (err) {
            console.error('Failed to fetch report', err);
            setReportData(null);
        } finally {
            setLoading(false);
        }
    };

    const exportToPDF = () => {
        try {
            const DocConstructor = getJsPDF();
            if (!DocConstructor) {
                throw new Error("jsPDF library not found");
            }

            const doc = new DocConstructor();
            const at = getAutoTable(doc);

            console.log('PDF Export Diagnostics:', {
                reportType,
                reportDataPresent: !!reportData,
                hasAutoTable: !!at,
                jsPDF_Type: typeof DocConstructor
            });

            if (!reportData) {
                console.warn('No report data available for export');
                return;
            }

            const pageWidth = doc.internal.pageSize.width;
            const pageHeight = doc.internal.pageSize.height;

            // Enhanced Header Background
            doc.setFillColor(15, 23, 42); // --bg-dark
            doc.rect(0, 0, pageWidth, 45, 'F');

            // Branding / Logo Placeholder Simulation
            doc.setTextColor(59, 130, 246); // --accent-primary
            doc.setFontSize(24);
            doc.setFont('helvetica', 'bold');
            doc.text("AutoDefenceX", 14, 20);

            doc.setTextColor(255, 255, 255);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.text("CYBER DEFENCE & SYSTEM POLICY SUITE", 14, 28);

            // Title
            const title = `${reportType.replace('-', ' ').toUpperCase()} REPORT`;
            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text(title, pageWidth - 14, 25, { align: 'right' });

            // Metadata
            doc.setFontSize(8);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(148, 163, 184); // --text-secondary
            doc.text(`Generated on: ${new Date().toLocaleString()}`, pageWidth - 14, 32, { align: 'right' });
            doc.text(`Organization: Admin Suite Internal`, pageWidth - 14, 37, { align: 'right' });

            let yPos = 60;

            // Add report data based on type with custom table styling
            if (reportType === 'all-employees' && reportData.employees && at) {
                at(doc, {
                    startY: yPos,
                    head: [['ID', 'Username', 'Full Name', 'Role', 'Risk', 'Status']],
                    body: reportData.employees.map(e => [e.id, e.username, e.full_name || 'N/A', e.role, e.risk_score?.toFixed(1) || '0.0', e.is_active ? 'Active' : 'Inactive']),
                    theme: 'striped',
                    headStyles: {
                        fillColor: [37, 99, 235], // #2563eb
                        textColor: [255, 255, 255],
                        fontSize: 10,
                        fontStyle: 'bold'
                    },
                    alternateRowStyles: { fillColor: [241, 245, 249] },
                    styles: { fontSize: 9, cellPadding: 4 }
                });
            }
            else if (reportType === 'bugs' && reportData.recent_tickets && at) {
                at(doc, {
                    startY: yPos,
                    head: [['ID', 'Category', 'Status', 'Description', 'Created']],
                    body: reportData.recent_tickets.map(t => [t.id, t.category, t.status, t.description, new Date(t.created_at).toLocaleDateString()]),
                    theme: 'striped',
                    headStyles: {
                        fillColor: [239, 68, 68], // --danger
                        textColor: [255, 255, 255],
                        fontSize: 10,
                        fontStyle: 'bold'
                    },
                    alternateRowStyles: { fillColor: [254, 242, 242] },
                    styles: { fontSize: 9, cellPadding: 4 }
                });
            }
            else if (reportData && at) {
                // Summary Dashboard layout in PDF
                doc.setFontSize(12);
                doc.setTextColor(15, 23, 42);
                doc.setFont('helvetica', 'bold');
                doc.text("Report Summary Metrics", 14, yPos);
                yPos += 8;

                const summaryData = Object.entries(reportData.summary || {}).map(([k, v]) => [
                    k.replace(/_/g, ' ').toUpperCase(),
                    typeof v === 'number' ? v.toFixed(1) : String(v)
                ]);

                if (summaryData.length > 0) {
                    at(doc, {
                        startY: yPos,
                        head: [['Metric Definition', 'Operational Value']],
                        body: summaryData,
                        theme: 'grid',
                        headStyles: { fillColor: [71, 85, 105], textColor: [255, 255, 255] },
                        styles: { fontSize: 9 }
                    });
                }
            }

            // Footer
            const finalY = doc.lastAutoTable ? doc.lastAutoTable.finalY + 20 : yPos + 20;
            doc.setFontSize(8);
            doc.setTextColor(148, 163, 184);
            doc.text("Confidential Information - AutoDefenceX Security Reports", 14, pageHeight - 10);
            doc.text(`Page 1`, pageWidth - 20, pageHeight - 10);

            console.log('Attempting to save PDF...');
            const filename = `AutoDefenceX-${reportType || 'report'}-${new Date().toISOString().split('T')[0]}.pdf`;

            // Use Blob-based download with explicit MIME type for correct filename
            const pdfArrayBuffer = doc.output('arraybuffer');
            const pdfBlob = new Blob([pdfArrayBuffer], { type: 'application/pdf' });
            const blobUrl = URL.createObjectURL(pdfBlob);
            const downloadLink = document.createElement('a');
            downloadLink.href = blobUrl;
            downloadLink.setAttribute('download', filename);
            downloadLink.style.display = 'none';
            document.body.appendChild(downloadLink);
            downloadLink.click();

            // Cleanup after a short delay
            setTimeout(() => {
                document.body.removeChild(downloadLink);
                URL.revokeObjectURL(blobUrl);
            }, 150);
            console.log('PDF Export complete.');
        } catch (error) {
            console.error('CRITICAL: PDF Export failed', error);
            alert('Failed to generate PDF. Check console for details.');
        }
    };


    // --- PERSONAL (USER) VIEW ---
    const role = JSON.parse(localStorage.getItem('user_info') || '{}').role;
    const currentUserId = JSON.parse(localStorage.getItem('user_info') || '{}').id;

    // Set default report type for non-admins
    useEffect(() => {
        if (role !== 'admin') {
            setReportType('my-activity');
            // Mock fetching data for "my-activity" since backend endpoint for it might need adjustment
            // For now we can reuse 'employee' endpoint logic but hardcoded to self or simplified
        }
    }, [role]);

    // ... (keep fetchUsers and fetchReport logic, but we'll modify render logic lower down)

    const renderEmployeeReport = () => (
        <div className="report-content">
            <div className="report-section">
                <h3>Employee Details</h3>
                <div className="stats-grid">
                    <div className="metric-box blue-border">
                        <h4>Full Name</h4>
                        <p>{reportData?.employee?.full_name || 'N/A'}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Employee ID</h4>
                        <p>{reportData?.employee?.employee_id || 'N/A'}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Job Title</h4>
                        <p>{reportData?.employee?.job_title || 'N/A'}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Risk Score</h4>
                        <p className={`metric-value-huge ${reportData?.employee?.risk_score > 7 ? 'text-red' : 'text-green'}`}>
                            {reportData?.employee?.risk_score?.toFixed(1) || '0.0'}
                        </p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Statistics</h3>
                <div className="stats-grid">
                    <div className="metric-box green-border">
                        <h4>Total Tickets</h4>
                        <p>{reportData?.statistics?.total_tickets || 0}</p>
                    </div>
                    <div className="metric-box yellow-border">
                        <h4>Open Tickets</h4>
                        <p>{reportData?.statistics?.open_tickets || 0}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Closed Tickets</h4>
                        <p>{reportData?.statistics?.closed_tickets || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Activities Logged</h4>
                        <p>{reportData?.statistics?.total_activities || 0}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Recent Tickets</h3>
                <div className="table-container">
                    {reportData?.recent_tickets?.length > 0 ? (
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Category</th>
                                    <th>Status</th>
                                    <th>Description</th>
                                    <th>Created</th>
                                </tr>
                            </thead>
                            <tbody>
                                {reportData.recent_tickets.map(ticket => (
                                    <tr key={ticket.id}>
                                        <td>#{ticket.id}</td>
                                        <td><span className="badge blue">{ticket.category}</span></td>
                                        <td><span className={`badge ${ticket.status === 'open' ? 'badge-danger' : 'badge-success'}`}>{ticket.status}</span></td>
                                        <td className="truncate">{ticket.description}</td>
                                        <td>{ticket.created_at ? new Date(ticket.created_at).toLocaleDateString() : 'N/A'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    ) : (
                        <p className="empty-state">No tickets found</p>
                    )}
                </div>
            </div>
        </div>
    );

    const renderAllEmployeesReport = () => (
        <div className="report-content">
            <div className="report-section">
                <h3>Summary</h3>
                <div className="stats-grid">
                    <div className="metric-box blue-border">
                        <h4>Total Users</h4>
                        <p>{reportData?.summary?.total_users || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Active Users</h4>
                        <p>{reportData?.summary?.active_users || 0}</p>
                    </div>
                    <div className="metric-box yellow-border">
                        <h4>Total Tickets</h4>
                        <p>{reportData?.summary?.total_tickets || 0}</p>
                    </div>
                    <div className="metric-box red-border">
                        <h4>Open Tickets</h4>
                        <p>{reportData?.summary?.open_tickets || 0}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Total Endpoints</h4>
                        <p>{reportData?.summary?.total_endpoints || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Online Endpoints</h4>
                        <p>{reportData?.summary?.online_endpoints || 0}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Risk Analysis</h3>
                <div className="stats-grid">
                    <div className="metric-box red-border">
                        <h4>High Risk Users</h4>
                        <p>{reportData?.risk_analysis?.high_risk_users || 0}</p>
                    </div>
                    <div className="metric-box yellow-border">
                        <h4>Medium Risk Users</h4>
                        <p>{reportData?.risk_analysis?.medium_risk_users || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Low Risk Users</h4>
                        <p>{reportData?.risk_analysis?.low_risk_users || 0}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>All Employees</h3>
                <div className="table-container">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Full Name</th>
                                <th>Job Title</th>
                                <th>Role</th>
                                <th>Risk Score</th>
                                <th>Tickets</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reportData?.employees?.map(emp => (
                                <tr key={emp.id}>
                                    <td>{emp.id}</td>
                                    <td>{emp.username}</td>
                                    <td>{emp.full_name || 'N/A'}</td>
                                    <td>{emp.job_title || 'N/A'}</td>
                                    <td><span className="badge blue">{emp.role}</span></td>
                                    <td className={emp.risk_score > 7 ? 'text-red' : emp.risk_score > 4 ? 'text-yellow' : 'text-green'}>
                                        {emp.risk_score?.toFixed(1) || '0.0'}
                                    </td>
                                    <td>{emp.ticket_count}</td>
                                    <td><span className={`badge ${emp.is_active ? 'green' : 'red'}`}>{emp.is_active ? 'Active' : 'Inactive'}</span></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );

    const renderBugsReport = () => (
        <div className="report-content">
            <div className="report-section">
                <h3>Ticket Summary</h3>
                <div className="stats-grid">
                    <div className="metric-box blue-border">
                        <h4>Total Tickets</h4>
                        <p>{reportData.summary?.total_tickets || 0}</p>
                    </div>
                    {reportData.summary?.by_status && Object.entries(reportData.summary.by_status).map(([status, count]) => (
                        <div key={status} className="metric-box green-border">
                            <h4>{status.toUpperCase()}</h4>
                            <p>{count}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="report-section">
                <h3>By Category</h3>
                <div className="stats-grid">
                    {reportData.summary?.by_category && Object.entries(reportData.summary.by_category).map(([category, count]) => (
                        <div key={category} className="metric-box blue-border">
                            <h4>{category.replace('_', ' ')}</h4>
                            <p>{count}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="report-section">
                <h3>Recent Tickets</h3>
                <div className="table-container">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>User ID</th>
                                <th>Category</th>
                                <th>Status</th>
                                <th>Description</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
                            {reportData?.recent_tickets?.map(ticket => (
                                <tr key={ticket.id}>
                                    <td>#{ticket.id}</td>
                                    <td>{ticket.user_id}</td>
                                    <td><span className="badge blue">{ticket.category}</span></td>
                                    <td><span className={`badge ${ticket.status === 'open' ? 'badge-danger' : 'badge-success'}`}>{ticket.status}</span></td>
                                    <td className="truncate">{ticket.description}</td>
                                    <td>{ticket.created_at ? new Date(ticket.created_at).toLocaleDateString() : 'N/A'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );

    const renderSecurityReport = () => (
        <div className="report-content">
            <div className="report-section">
                <h3>Security Overview</h3>
                <div className="stats-grid">
                    <div className="metric-box red-border">
                        <h4>High Risk Users</h4>
                        <p>{reportData?.summary?.high_risk_users_count || 0}</p>
                    </div>
                    <div className="metric-box red-border">
                        <h4>High Risk Endpoints</h4>
                        <p>{reportData?.summary?.high_risk_endpoints_count || 0}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Total Endpoints</h4>
                        <p>{reportData?.summary?.total_endpoints || 0}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Endpoint Risk Distribution</h3>
                <div className="stats-grid">
                    <div className="metric-box red-border">
                        <h4>High Risk</h4>
                        <p>{reportData?.summary?.endpoint_risk_distribution?.high || 0}</p>
                    </div>
                    <div className="metric-box yellow-border">
                        <h4>Medium Risk</h4>
                        <p>{reportData?.summary?.endpoint_risk_distribution?.medium || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Low Risk</h4>
                        <p>{reportData?.summary?.endpoint_risk_distribution?.low || 0}</p>
                    </div>
                </div>
            </div>

            {reportData?.high_risk_users?.length > 0 && (
                <div className="report-section">
                    <h3>High Risk Users</h3>
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Full Name</th>
                                    <th>Role</th>
                                    <th>Risk Score</th>
                                </tr>
                            </thead>
                            <tbody>
                                {reportData.high_risk_users.map(user => (
                                    <tr key={user.id}>
                                        <td>{user.id}</td>
                                        <td>{user.username}</td>
                                        <td>{user.full_name || 'N/A'}</td>
                                        <td><span className="badge blue">{user.role}</span></td>
                                        <td className="text-red">{user.risk_score?.toFixed(1) || '0.0'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {reportData?.high_risk_endpoints?.length > 0 && (
                <div className="report-section">
                    <h3>High Risk Endpoints</h3>
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Hostname</th>
                                    <th>IP Address</th>
                                    <th>Risk Level</th>
                                    <th>Status</th>
                                    <th>Last Seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                {reportData?.high_risk_endpoints?.map(endpoint => (
                                    <tr key={endpoint.id}>
                                        <td>{endpoint.id}</td>
                                        <td>{endpoint.hostname}</td>
                                        <td>{endpoint.ip_address}</td>
                                        <td><span className="badge red">{endpoint.risk_level}</span></td>
                                        <td><span className={`badge ${endpoint.status === 'online' ? 'green' : 'red'}`}>{endpoint.status}</span></td>
                                        <td>{endpoint.last_seen ? new Date(endpoint.last_seen).toLocaleString() : 'N/A'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );



    const renderSystemHealthReport = () => (
        <div className="report-content">
            <div className="report-section">
                <h3>System Status</h3>
                <div className="stats-grid">
                    <div className="metric-box green-border">
                        <h4>System Status</h4>
                        <p className="text-green">{reportData?.summary?.system_status || 'Unknown'}</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Total Endpoints</h4>
                        <p>{reportData?.summary?.total_endpoints || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Online</h4>
                        <p>{reportData?.summary?.online_endpoints || 0}</p>
                    </div>
                    <div className="metric-box red-border">
                        <h4>Offline</h4>
                        <p>{reportData?.summary?.offline_endpoints || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Uptime</h4>
                        <p>{reportData?.summary?.uptime_percentage?.toFixed(1) || '0.0'}%</p>
                    </div>
                    <div className="metric-box blue-border">
                        <h4>Avg Trust Score</h4>
                        <p>{reportData?.summary?.average_trust_score || 0}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Performance Metrics</h3>
                <div className="stats-grid">
                    <div className="metric-box yellow-border">
                        <h4>Tickets (24h)</h4>
                        <p>{reportData?.performance_metrics?.tickets_last_24h || 0}</p>
                    </div>
                    <div className="metric-box red-border">
                        <h4>Open Tickets</h4>
                        <p>{reportData?.performance_metrics?.total_open_tickets || 0}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Avg Response Time</h4>
                        <p>{reportData?.performance_metrics?.response_time_avg || 'N/A'}</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>Resolution Rate</h4>
                        <p>{reportData?.performance_metrics?.resolution_rate || '0%'}</p>
                    </div>
                </div>
            </div>

            <div className="report-section">
                <h3>Health Indicators</h3>
                <div className="stats-grid">
                    {reportData?.health_indicators && Object.entries(reportData.health_indicators).map(([key, value]) => (
                        <div key={key} className="metric-box green-border">
                            <h4>{key.replace('_', ' ').toUpperCase()}</h4>
                            <p className={value === 'Good' || value === 'Strong' || value === 'High' || value === 'Normal' ? 'text-green' : 'text-yellow'}>
                                {value}
                            </p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );

    const renderReportContent = () => {
        if (loading) {
            return <div className="loading-state">Generating report...</div>;
        }

        if (!reportData && role === 'admin') {
            return <div className="empty-state">Select parameters and click Generate to view report</div>;
        }

        if (role !== 'admin' && !reportData) {
            return <div className="empty-state">Click Generate to view your activity report</div>;
        }

        switch (reportType) {
            case 'employee':
            case 'my-activity':
                return renderEmployeeReport();
            case 'all-employees':
                return renderAllEmployeesReport();
            case 'bugs':
                return renderBugsReport();
            case 'security':
                return renderSecurityReport();

            case 'system-health':
                return renderSystemHealthReport();
            default:
                return null;
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><FileText className="icon-lg" /> Reports & Analytics</h2>
                <div className="export-controls-header">
                    <button
                        className="export-pdf-btn-glass"
                        onClick={exportToPDF}
                        disabled={!reportData}
                        title="Download Premium PDF Report"
                    >
                        <FileDown size={18} />
                        <span>Export Report</span>
                    </button>
                </div>
            </header>

            <div className="card full-width">
                <div className="report-controls">
                    {role === 'admin' ? (
                        <div className="form-group">
                            <label><Filter size={16} /> Report Type</label>
                            <select
                                className="cyber-input"
                                value={reportType}
                                onChange={(e) => setReportType(e.target.value)}
                            >
                                <option value="all-employees">All Employees Report</option>
                                <option value="employee">Per-Employee Report</option>
                                <option value="bugs">Bug/Ticket Report</option>
                                <option value="security">Security Report</option>

                                <option value="system-health">System Health Report</option>
                            </select>
                        </div>
                    ) : (
                        <div className="form-group">
                            <label><Filter size={16} /> Report Type</label>
                            <select className="cyber-input" disabled value="my-activity">
                                <option value="my-activity">My Activity Report</option>
                            </select>
                        </div>
                    )}

                    <div className="form-group">
                        <label>Start Date</label>
                        <input
                            type="date"
                            className="cyber-input"
                            value={startDate}
                            onChange={(e) => setStartDate(e.target.value)}
                        />
                    </div>

                    <div className="form-group">
                        <label>End Date</label>
                        <input
                            type="date"
                            className="cyber-input"
                            value={endDate}
                            onChange={(e) => setEndDate(e.target.value)}
                        />
                    </div>

                    {reportType === 'employee' && (
                        <div className="form-group">
                            <label><Users size={16} /> Select Employee</label>
                            <select
                                className="cyber-input"
                                value={selectedUserId}
                                onChange={(e) => setSelectedUserId(e.target.value)}
                            >
                                <option value="">-- Select Employee --</option>
                                {users.map(user => (
                                    <option key={user.id} value={user.id}>
                                        {user.full_name || user.username} ({user.employee_id || user.username})
                                    </option>
                                ))}
                            </select>
                        </div>
                    )}

                    <div className="form-group full-width centered-button-container">
                        <button
                            className="action-btn large-btn"
                            onClick={fetchReport}
                            disabled={reportType === 'employee' && !selectedUserId}
                        >
                            Generate Report
                        </button>
                    </div>
                </div>

                {generatedAt && (
                    <div className="report-header">
                        <p className="report-meta">
                            Generated: {generatedAt}
                        </p>
                    </div>
                )}
            </div>

            {renderReportContent()}
        </div>
    );
};

export default Reports;
