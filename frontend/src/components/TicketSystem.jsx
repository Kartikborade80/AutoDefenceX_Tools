import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Ticket, Plus, Clock, CheckCircle, X, User, MessageCircle, Building, Eye } from 'lucide-react';

const TicketSystem = () => {
    const [tickets, setTickets] = useState([]);
    const [showModal, setShowModal] = useState(false);
    const [showViewModal, setShowViewModal] = useState(false);
    const [selectedTicket, setSelectedTicket] = useState(null);
    const [departments, setDepartments] = useState([]);
    const [activeUsers, setActiveUsers] = useState([]);
    const [newTicket, setNewTicket] = useState({
        assigned_to_user_id: '',
        department_id: '',
        description: ''
    });

    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const isAdmin = userInfo.role === 'admin';

    useEffect(() => {
        fetchTickets();
        fetchDepartments();
        fetchActiveUsers();
    }, []);

    const fetchTickets = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/users/tickets', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setTickets(res.data);
        } catch (err) {
            console.error("Failed to fetch tickets", err);
        }
    };

    const fetchDepartments = async () => {
        try {
            const res = await axios.get('/departments/');
            setDepartments(res.data);
        } catch (err) {
            console.error("Failed to fetch departments", err);
        }
    };

    const fetchActiveUsers = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/users/active', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setActiveUsers(res.data);
        } catch (err) {
            console.error("Failed to fetch active users", err);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem('token');
            const payload = {
                description: newTicket.description,
                status: 'open',
                assigned_to_user_id: newTicket.assigned_to_user_id ? parseInt(newTicket.assigned_to_user_id) : null,
                department_id: newTicket.department_id ? parseInt(newTicket.department_id) : null
            };

            await axios.post('/users/tickets', payload, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setShowModal(false);
            setNewTicket({ assigned_to_user_id: '', department_id: '', description: '' });
            fetchTickets();
        } catch (err) {
            console.error('Ticket submission error:', err);
        }
    };

    const updateTicketStatus = async (ticketId, newStatus) => {
        try {
            const token = localStorage.getItem('token');
            await axios.patch(`/users/tickets/${ticketId}`, { status: newStatus }, {
                headers: { Authorization: `Bearer ${token}` }
            });
            fetchTickets();
            if (selectedTicket && selectedTicket.id === ticketId) {
                setSelectedTicket({ ...selectedTicket, status: newStatus });
            }
        } catch (err) {
            console.error('Failed to update ticket status', err);
        }
    };

    const getDeptName = (deptId) => {
        const dept = departments.find(d => d.id === deptId);
        return dept ? dept.name : 'Unknown';
    };

    const getAssigneeName = (userId) => {
        if (!userId) return 'Unassigned';
        const user = activeUsers.find(u => u.id === userId);
        return user ? (user.full_name || user.username) : `User #${userId}`;
    };

    const handleViewTicket = (ticket) => {
        setSelectedTicket(ticket);
        setShowViewModal(true);
    };

    return (
        <div className="ticket-system-container slide-up">
            <header className="page-header">
                <div className="header-title-area">
                    <h2><Ticket size={28} /> {isAdmin ? "Support Ticket Center" : "My Support Tickets"}</h2>
                    <p className="text-muted">Raise and track technical support requests with our IT team.</p>
                </div>
                <div className="header-actions">
                    <button className="btn-primary" onClick={() => setShowModal(true)}>
                        <Plus size={18} /> Create New Ticket
                    </button>
                </div>
            </header>

            <div className="card table-card-modern">
                <div className="table-wrapper">
                    <table className="table-unified">
                        <thead>
                            <tr>
                                <th>Ticket ID</th>
                                <th>Generated On</th>
                                <th>Issue Details</th>
                                <th>Target Dept</th>
                                <th>Assigned Agent</th>
                                <th>Status</th>
                                <th style={{ textAlign: 'right' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {tickets.length === 0 ? (
                                <tr><td colSpan="7" className="no-data-cell">No active cases found.</td></tr>
                            ) : (
                                tickets.map(t => (
                                    <tr key={t.id}>
                                        <td className="font-mono text-brand">Ticket-#{t.id}</td>
                                        <td className="text-muted">{new Date(t.created_at).toLocaleDateString()}</td>
                                        <td>
                                            <div className="ticket-description-cell" title={t.description}>
                                                <MessageCircle size={14} className="text-muted" />
                                                <span>{t.description}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <div className="user-assignee-pill">
                                                <Building size={12} />
                                                <span>{t.department_id ? getDeptName(t.department_id) : 'Unassigned'}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <div className="user-assignee-pill">
                                                <User size={12} />
                                                <span>{t.assigned_to_user_id ? `Agent ${t.assigned_to_user_id}` : 'Queueing'}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <span className={`status-pill-modern ${t.status}`}>
                                                {t.status}
                                            </span>
                                        </td>
                                        <td style={{ textAlign: 'right' }}>
                                            <div className="action-buttons-row" style={{ justifyContent: 'flex-end', display: 'flex', gap: '8px' }}>
                                                <button
                                                    className="btn-icon-only"
                                                    title="View Details"
                                                    onClick={() => handleViewTicket(t)}
                                                >
                                                    <Eye size={16} className="text-blue" />
                                                </button>

                                                {isAdmin ? (
                                                    <select
                                                        className="form-input btn-sm status-select"
                                                        value={t.status}
                                                        onChange={(e) => updateTicketStatus(t.id, e.target.value)}
                                                    >
                                                        <option value="open">Open</option>
                                                        <option value="in_progress">In Progress</option>
                                                        <option value="solved">Solved</option>
                                                    </select>
                                                ) : (
                                                    t.status !== 'solved' && (
                                                        <button
                                                            className="btn-secondary btn-sm"
                                                            onClick={() => updateTicketStatus(t.id, 'solved')}
                                                            title="Mark as Solved"
                                                        >
                                                            <CheckCircle size={14} />
                                                        </button>
                                                    )
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Create Ticket Modal */}
            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content premium-modal slide-up">
                        <div className="modal-header">
                            <div className="header-icon-box">
                                <Ticket size={24} className="text-brand" />
                            </div>
                            <div className="header-text">
                                <h3>Create Support Ticket</h3>
                                <p>Provide details about your technical issue.</p>
                            </div>
                            <button onClick={() => setShowModal(false)} className="close-btn"><X size={20} /></button>
                        </div>
                        <form onSubmit={handleSubmit} className="premium-form">
                            <div className="form-row-modern">
                                <div className="form-group flex-1">
                                    <label>Target Department</label>
                                    <div className="input-wrapper">
                                        <Building size={18} className="input-icon" />
                                        <select
                                            className="form-input has-icon"
                                            value={newTicket.department_id}
                                            onChange={e => {
                                                const deptId = e.target.value;
                                                setNewTicket({ ...newTicket, department_id: deptId, assigned_to_user_id: '' });
                                                if (deptId) {
                                                    const token = localStorage.getItem('token');
                                                    axios.get(`/users/active?department_id=${deptId}`, {
                                                        headers: { Authorization: `Bearer ${token}` }
                                                    }).then(res => setActiveUsers(res.data));
                                                } else {
                                                    fetchActiveUsers();
                                                }
                                            }}
                                            required
                                        >
                                            <option value="">-- Select Department --</option>
                                            {departments.map(dept => (
                                                <option key={dept.id} value={dept.id}>{dept.name}</option>
                                            ))}
                                        </select>
                                    </div>
                                </div>
                                <div className="form-group flex-1">
                                    <label>Assign To (Optional)</label>
                                    <div className="input-wrapper">
                                        <User size={18} className="input-icon" />
                                        <select
                                            className="form-input has-icon"
                                            value={newTicket.assigned_to_user_id}
                                            onChange={e => setNewTicket({ ...newTicket, assigned_to_user_id: e.target.value })}
                                        >
                                            <option value="">-- Unassigned --</option>
                                            {activeUsers.map(user => (
                                                <option key={user.id} value={user.id}>
                                                    {user.full_name || user.username} ({user.job_title || user.role})
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                </div>
                            </div>
                            <div className="form-group">
                                <label>Detailed Description</label>
                                <textarea
                                    className="form-input"
                                    rows="6"
                                    value={newTicket.description}
                                    onChange={e => setNewTicket({ ...newTicket, description: e.target.value })}
                                    required
                                    placeholder="Describe the problem, error messages, and steps to reproduce..."
                                />
                            </div>
                            <div className="modal-footer-actions">
                                <button type="button" className="btn-secondary" onClick={() => setShowModal(false)}>Discard</button>
                                <button type="submit" className="btn-primary">Submit Support Ticket</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* View Ticket Modal */}
            {showViewModal && selectedTicket && (
                <div className="modal-overlay">
                    <div className="modal-content premium-modal slide-up">
                        <div className="modal-header">
                            <div className="header-icon-box">
                                <Ticket size={24} className="text-brand" />
                            </div>
                            <div className="header-text">
                                <h3>Ticket Details</h3>
                                <p className="font-mono text-muted">ID: Ticket-#{selectedTicket.id}</p>
                            </div>
                            <button onClick={() => setShowViewModal(false)} className="close-btn"><X size={20} /></button>
                        </div>

                        <div className="ticket-details-grid">
                            <div className="detail-item">
                                <label>Status</label>
                                <span className={`status-pill-modern ${selectedTicket.status}`}>
                                    {selectedTicket.status}
                                </span>
                            </div>
                            <div className="detail-item">
                                <label>Target Department</label>
                                <div className="detail-value">
                                    <Building size={14} className="text-muted" />
                                    <span>{selectedTicket.department_id ? getDeptName(selectedTicket.department_id) : 'Unassigned'}</span>
                                </div>
                            </div>
                            <div className="detail-item">
                                <label>Assigned Agent</label>
                                <div className="detail-value">
                                    <User size={14} className="text-muted" />
                                    <span>{getAssigneeName(selectedTicket.assigned_to_user_id)}</span>
                                </div>
                            </div>
                            <div className="detail-item">
                                <label>Created On</label>
                                <div className="detail-value">
                                    <Clock size={14} className="text-muted" />
                                    <span>{new Date(selectedTicket.created_at).toLocaleString()}</span>
                                </div>
                            </div>
                        </div>

                        <div className="detail-section mt-4">
                            <label>Issue Description</label>
                            <div className="description-box">
                                {selectedTicket.description}
                            </div>
                        </div>

                        <div className="modal-footer-actions">
                            <button type="button" className="btn-secondary" onClick={() => setShowViewModal(false)}>Close</button>
                            {isAdmin ? (
                                <div style={{ display: 'flex', gap: '8px' }}>
                                    {selectedTicket.status !== 'solved' && (
                                        <button className="btn-primary" onClick={() => { updateTicketStatus(selectedTicket.id, 'solved'); setShowViewModal(false); }}>Mark Solved</button>
                                    )}
                                </div>
                            ) : (
                                selectedTicket.status !== 'solved' && (
                                    <button className="btn-primary" onClick={() => { updateTicketStatus(selectedTicket.id, 'solved'); setShowViewModal(false); }}>Mark Solved</button>
                                )
                            )}
                        </div>
                    </div>
                </div>
            )}


        </div>
    );
};

export default TicketSystem;
