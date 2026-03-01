import React from 'react';
import { ClipboardList, Clock, CheckCircle2, AlertCircle } from 'lucide-react';
import './Dashboard.css';

const Tasks = () => {
    const tasks = [
        { id: 1, title: 'Complete Security Audit', priority: 'High', status: 'In Progress', due: '2026-03-01' },
        { id: 2, title: 'Update Firewall Rules', priority: 'Medium', status: 'Pending', due: '2026-03-05' },
        { id: 3, title: 'Employee Training Session', priority: 'Low', status: 'Completed', due: '2026-02-25' },
    ];

    const getStatusIcon = (status) => {
        switch (status) {
            case 'Completed': return <CheckCircle2 className="text-green-400" size={18} />;
            case 'In Progress': return <Clock className="text-blue-400" size={18} />;
            default: return <AlertCircle className="text-yellow-400" size={18} />;
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><ClipboardList className="icon-lg" /> Task Management</h2>
                <button className="btn-modern-primary">Create New Task</button>
            </header>

            <div className="grid-container">
                <div className="card full-width no-padding-card">
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Task ID</th>
                                    <th>Description</th>
                                    <th>Priority</th>
                                    <th>Due Date</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {tasks.map(t => (
                                    <tr key={t.id}>
                                        <td className="text-mono">#TSK-{String(t.id).padStart(3, '0')}</td>
                                        <td className="text-white font-medium">{t.title}</td>
                                        <td>
                                            <span className={`badge ${t.priority === 'High' ? 'badge-critical' : t.priority === 'Medium' ? 'badge-warning' : 'badge-info'}`}>
                                                {t.priority}
                                            </span>
                                        </td>
                                        <td className="text-muted">{t.due}</td>
                                        <td>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                {getStatusIcon(t.status)}
                                                <span>{t.status}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <button className="btn-modern-primary btn-modern-sm">Edit</button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Tasks;
