import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Building, Plus, Edit, Trash2 } from 'lucide-react';
import './Dashboard.css';

const Departments = () => {
    const [departments, setDepartments] = useState([]);
    const [showModal, setShowModal] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [selectedDeptId, setSelectedDeptId] = useState(null);
    const [newDept, setNewDept] = useState({ name: '', description: '', hod_id: '', monitoring_enabled: false });
    const [users, setUsers] = useState([]);
    const [notification, setNotification] = useState('');

    useEffect(() => {
        fetchDepartments();
        fetchUsers();
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

    const fetchDepartments = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/departments/', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setDepartments(res.data);
        } catch (err) {
            console.error('Failed to fetch departments', err);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem('token');
            const payload = { ...newDept };
            if (payload.hod_id === "") payload.hod_id = null;
            else payload.hod_id = parseInt(payload.hod_id);

            if (isEditing) {
                await axios.put(`/departments/${selectedDeptId}`, payload, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setNotification('Department updated successfully.');
            } else {
                await axios.post('/departments/', payload, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setNotification('Department created successfully.');
            }
            setShowModal(false);
            resetForm();
            fetchDepartments();
            setTimeout(() => setNotification(''), 3000);
        } catch (err) {
            console.error(err);
            setNotification('Failed to save department. Name might already exist.');
            setTimeout(() => setNotification(''), 3000);
        }
    };

    const resetForm = () => {
        setNewDept({ name: '', description: '', hod_id: '', monitoring_enabled: false });
        setIsEditing(false);
        setSelectedDeptId(null);
    };

    const handleEdit = (dept) => {
        setNewDept({
            name: dept.name,
            description: dept.description || '',
            hod_id: dept.hod_id || '',
            monitoring_enabled: dept.monitoring_enabled || false
        });
        setSelectedDeptId(dept.id);
        setIsEditing(true);
        setShowModal(true);
    };

    const handleDelete = async (deptId) => {
        if (!window.confirm('Are you sure you want to delete this department?')) return;

        try {
            const token = localStorage.getItem('token');
            await axios.delete(`/departments/${deptId}`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setNotification('Department deleted successfully.');
            fetchDepartments();
            setTimeout(() => setNotification(''), 3000);
        } catch (err) {
            console.error(err);
            const msg = err.response?.data?.detail || 'Failed to delete department.';
            setNotification(msg);
            setTimeout(() => setNotification(''), 5000);
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="page-header">
                <h2><Building className="icon-lg" /> Department Management</h2>
                <button className="btn-primary" onClick={() => { resetForm(); setShowModal(true); }}>
                    <Plus size={16} /> Create Department
                </button>
            </header>

            {notification && <div className="alert-item info">{notification}</div>}

            <div className="grid-container">
                <div className="card full-width">
                    <h3>All Departments</h3>
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Department Name</th>
                                    <th>Head of Dept (HOD)</th>
                                    <th>Strength</th>
                                    <th>Description</th>
                                    <th className="no-print">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {departments.length === 0 ? (
                                    <tr><td colSpan="6" className="empty-state">No departments found</td></tr>
                                ) : (
                                    departments.map(dept => {
                                        const deptUsers = users.filter(u => u.department_id === dept.id);
                                        return (
                                            <tr key={dept.id}>
                                                <td className="font-mono">#{dept.id}</td>
                                                <td><strong className="text-blue">{dept.name}</strong></td>
                                                <td>
                                                    {dept.hod_id ? (
                                                        <span className="badge badge-success">
                                                            {users.find(u => u.id === dept.hod_id)?.full_name || 'Assigned'}
                                                        </span>
                                                    ) : <span className="text-muted">Unassigned</span>}
                                                </td>
                                                <td>
                                                    <span className="badge badge-user">{deptUsers.length} Staff</span>
                                                </td>
                                                <td>
                                                    {dept.monitoring_enabled ? (
                                                        <span className="badge badge-agent">MONITORING ON</span>
                                                    ) : <span className="text-muted">Disabled</span>}
                                                </td>
                                                <td className="text-muted">{dept.description || 'N/A'}</td>
                                                <td className="no-print">
                                                    <button className="btn-modern-primary btn-modern-sm" onClick={() => handleEdit(dept)} style={{ marginRight: '8px' }}>Edit</button>
                                                    <button className="btn-modern-danger btn-modern-sm" onClick={() => handleDelete(dept.id)}>Delete</button>
                                                </td>
                                            </tr>
                                        );
                                    })
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content card slide-up">
                        <div className="modal-header">
                            <h3><Building className="text-blue" /> {isEditing ? 'Modify Organizational Unit' : 'Initialize New Department'}</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}>&times;</button>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label>Department Name</label>
                                <input
                                    type="text"
                                    className="form-input"
                                    value={newDept.name}
                                    onChange={e => setNewDept({ ...newDept, name: e.target.value })}
                                    required
                                    placeholder="e.g., IT Support, HR, Helpdesk"
                                />
                            </div>
                            <div className="form-group">
                                <label>Description</label>
                                <textarea
                                    className="form-input"
                                    rows="3"
                                    value={newDept.description}
                                    onChange={e => setNewDept({ ...newDept, description: e.target.value })}
                                    placeholder="Brief description of the department..."
                                />
                            </div>
                            <div className="form-group">
                                <label>Assign Head of Department (HOD)</label>
                                <select
                                    className="cyber-input"
                                    value={newDept.hod_id}
                                    onChange={e => setNewDept({ ...newDept, hod_id: e.target.value })}
                                >
                                    <option value="">-- Select HOD --</option>
                                    {users.map(user => (
                                        <option key={user.id} value={user.id}>
                                            {user.full_name || user.username} ({user.job_title || user.role})
                                        </option>
                                    ))}
                                </select>
                            </div>
                            <div className="form-group" style={{ gridColumn: '1 / -1', marginTop: '10px' }}>
                                <label className="checkbox-label" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                    <input
                                        type="checkbox"
                                        checked={newDept.monitoring_enabled}
                                        onChange={e => setNewDept({ ...newDept, monitoring_enabled: e.target.checked })}
                                    />
                                    <strong>Enable Real-Time Monitoring for HOD</strong>
                                </label>
                                <p className="subtitle" style={{ fontSize: '0.8rem', marginLeft: '25px', color: 'var(--text-secondary)' }}>
                                    Grants this department's head access to the live surveillance dashboard.
                                </p>
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="btn-modern-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                                <button type="submit" className="btn-modern-primary">{isEditing ? 'Update Records' : 'Create Department'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Departments;
