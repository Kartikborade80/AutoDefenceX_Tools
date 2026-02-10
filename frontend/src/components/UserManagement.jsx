import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Users, Plus, ShieldCheck, UserCheck, Briefcase, Smartphone, Monitor, CheckCircle, Building } from 'lucide-react';
import OTPVerificationModal from './OTPVerificationModal';
import './Dashboard.css';
import './ExactScreenshotStyles.css';

const UserManagement = () => {
    const [users, setUsers] = useState([]);
    const [departments, setDepartments] = useState([]);
    const [showModal, setShowModal] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [selectedUserId, setSelectedUserId] = useState(null);
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const [newUser, setNewUser] = useState({
        username: '',
        password: '',
        role: 'Support',
        full_name: '',
        employee_id: '',
        mobile_number: '',
        email: '',
        job_title: '',
        designation_code: '',
        account_type: 'Permanent',
        department_id: '',
        access_level: 'Full Access',
        os_type: 'Windows 11',
        hostname: '',
        device_id: '',
        access_expiry: '',
        password_expiry_days: 90,
        force_password_change: false,
        created_by: 'Admin',
        is_normal_user: true,
        is_department_head: false
    });
    const [notification, setNotification] = useState('');
    const [showOTPModal, setShowOTPModal] = useState(false);
    const [otpTargetUser, setOtpTargetUser] = useState(null);

    useEffect(() => {
        fetchUsers();
        fetchDepartments();
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

    const resetForm = () => {
        setNewUser({
            username: '',
            password: '',
            role: userInfo.is_department_head ? 'user' : 'Support',
            full_name: '',
            employee_id: '',
            mobile_number: '',
            email: '',
            job_title: '',
            designation_code: '',
            account_type: 'Permanent',
            department_id: userInfo.is_department_head ? userInfo.department_id : '',
            access_level: 'Full Access',
            os_type: 'Windows 11',
            hostname: '',
            device_id: '',
            access_expiry: '',
            password_expiry_days: 90,
            force_password_change: false,
            created_by: userInfo.username,
            is_normal_user: true,
            is_department_head: false
        });
        setIsEditing(false);
        setSelectedUserId(null);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const token = localStorage.getItem('token');
            const payload = { ...newUser };
            if (payload.department_id === "") payload.department_id = null;
            else payload.department_id = parseInt(payload.department_id);

            if (isEditing) {
                const originalUser = users.find(u => u.id === selectedUserId);
                if (payload.mobile_number && payload.mobile_number !== originalUser?.mobile_number) {
                    setOtpTargetUser({ ...payload, id: selectedUserId });
                    setShowOTPModal(true);
                    return;
                }

                const updatePayload = { ...payload };
                // Remove immutable fields not present in UserUpdate schema
                delete updatePayload.username;
                delete updatePayload.role;
                delete updatePayload.employee_id;
                delete updatePayload.created_by;
                delete updatePayload.access_level;

                // Handle optional fields types
                if (!updatePayload.password) delete updatePayload.password;
                if (updatePayload.access_expiry === "") updatePayload.access_expiry = null;
                if (updatePayload.password_expiry_days) updatePayload.password_expiry_days = parseInt(updatePayload.password_expiry_days);

                await axios.put(`/users/${selectedUserId}`, updatePayload, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setNotification('User updated successfully.');
            } else {
                const createPayload = { ...payload };
                delete createPayload.access_level; // Not in backend schema

                if (createPayload.access_expiry === "") createPayload.access_expiry = null;
                if (createPayload.password_expiry_days) createPayload.password_expiry_days = parseInt(createPayload.password_expiry_days);

                await axios.post('/users/', createPayload, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setNotification('User registered successfully.');
            }

            setShowModal(false);
            resetForm();
            setTimeout(() => {
                fetchUsers();
            }, 500);
            setTimeout(() => setNotification(''), 3000);
        } catch (err) {
            console.error(err);
            setNotification('Failed to save user.');
            setTimeout(() => setNotification(''), 3000);
        }
    };

    const handleFullNameChange = (e) => {
        const name = e.target.value;
        const newUserData = { ...newUser, full_name: name };

        if (!isEditing && name.trim().split(' ').length >= 2) {
            const parts = name.toLowerCase().split(' ');
            const username = `${parts[0]}.${parts[parts.length - 1]}`;
            const empId = `TM-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

            newUserData.username = username;
            newUserData.email = `${username}@infotech.com`;
            newUserData.employee_id = empId;
            newUserData.hostname = `IT-LAP-${empId}`;
            newUserData.password = Math.random().toString(36).slice(-10) + '!A1';
            newUserData.device_id = `DEV-LAP-${Math.floor(Math.random() * 1000)}`;
        }
        setNewUser(newUserData);
    };

    const handleEditClick = (user) => {
        setNewUser({
            username: user.username,
            password: '',
            role: user.role || 'Support',
            full_name: user.full_name || '',
            employee_id: user.employee_id || '',
            mobile_number: user.mobile_number || '',
            email: user.email || '',
            job_title: user.job_title || '',
            designation_code: user.designation_code || '',
            account_type: user.account_type || 'Permanent',
            department_id: user.department_id || '',
            access_level: user.access_level || 'Full Access',
            os_type: user.os_type || 'Windows 11',
            hostname: user.hostname || '',
            device_id: user.device_id || '',
            access_expiry: user.access_expiry ? user.access_expiry.split('T')[0] : '',
            password_expiry_days: user.password_expiry_days || 90,
            force_password_change: user.force_password_change || false,
            created_by: user.created_by || 'Admin',
            is_normal_user: user.is_normal_user ?? true,
            is_department_head: user.is_department_head || false
        });
        setSelectedUserId(user.id);
        setIsEditing(true);
        setShowModal(true);
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><Users className="icon-lg" /> Employee Directory & Access Control</h2>
                <div style={{ display: 'flex', gap: '10px' }}>
                    {(userInfo.role === 'admin' || userInfo.is_department_head) && (
                        <button className="btn-modern-primary" onClick={() => { resetForm(); setShowModal(true); }}>
                            <Plus size={16} /> {userInfo.is_department_head ? "Add Team Member" : "Add New User/Employee"}
                        </button>
                    )}
                </div>
            </header>

            {notification && <div className="alert-item info">{notification}</div>}

            <div className="grid-container">
                <div className="card full-width no-padding-card">
                    <div className="table-responsive">
                        <table className="table-unified">
                            <thead>
                                <tr>
                                    <th>Emp ID</th>
                                    <th>Full Name</th>
                                    <th>Department</th>
                                    <th>Role / Title</th>
                                    <th>Mobile</th>
                                    <th>Asset ID</th>
                                    <th>Type</th>
                                    <th className="no-print">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {users.map(u => {
                                    const dept = departments.find(d => d.id === u.department_id);
                                    return (
                                        <tr key={u.id}>
                                            <td className="text-white font-mono">{u.employee_id || 'TM-ADMIN-001'}</td>
                                            <td className="text-white font-medium">{u.full_name || u.username}</td>
                                            <td className="text-muted">{dept ? dept.name : 'Unassigned'}</td>
                                            <td className="text-white">{u.job_title || u.role}</td>
                                            <td className="text-mono">{u.mobile_number || '0000000000'}</td>
                                            <td className="text-mono">{u.asset_id || 'ASSET-GEN-932'}</td>
                                            <td>
                                                <span className={`badge ${!u.is_normal_user ? 'badge-agent' : 'badge-user'}`}>
                                                    {!u.is_normal_user ? 'AGENT' : 'USER'}
                                                </span>
                                            </td>
                                            <td className="no-print">
                                                <button className="btn-modern-primary btn-modern-sm" onClick={() => handleEditClick(u)}>Edit</button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {showModal && (
                <div className="modal-overlay">
                    <div className="modal-content card slide-up">
                        <div className="modal-header">
                            <h3><ShieldCheck className="text-blue" /> {isEditing ? 'Modify Personnel Access' : 'Register New Personnel'}</h3>
                            <button className="close-btn" onClick={() => setShowModal(false)}>&times;</button>
                        </div>
                        <form onSubmit={handleSubmit} className="cyber-form-scrollable" style={{ maxHeight: '70vh', overflowY: 'auto', paddingRight: '15px' }}>
                            <div className="form-grid">
                                <div className="form-group">
                                    <label><Users size={16} /> Full Name</label>
                                    <input type="text" className="cyber-input" value={newUser.full_name} onChange={handleFullNameChange} placeholder="Enter Full Name" required />
                                </div>
                                <div className="form-group">
                                    <label><CheckCircle size={16} /> Employee ID</label>
                                    <input type="text" className="cyber-input" value={newUser.employee_id} onChange={e => setNewUser({ ...newUser, employee_id: e.target.value })} placeholder="EMP001" />
                                </div>
                                <div className="form-group">
                                    <label>System Username</label>
                                    <input type="text" className="cyber-input" value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Company Email</label>
                                    <input type="email" className="cyber-input" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Access Key (Password)</label>
                                    <input type="text" className="cyber-input" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Password Expiry</label>
                                    <select className="cyber-input" value={newUser.password_expiry_days} onChange={e => setNewUser({ ...newUser, password_expiry_days: e.target.value })}>
                                        <option value="30">30 Days</option>
                                        <option value="60">60 Days</option>
                                        <option value="90">90 Days</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>User Role</label>
                                    <select
                                        className="cyber-input"
                                        value={newUser.role}
                                        onChange={e => setNewUser({ ...newUser, role: e.target.value })}
                                        disabled={userInfo.is_department_head} // Dept Head cannot change role
                                    >
                                        {!userInfo.is_department_head && <option value="Admin">Admin</option>}
                                        {!userInfo.is_department_head && <option value="HR">HR</option>}
                                        {!userInfo.is_department_head && <option value="Manager">Manager</option>}
                                        <option value="Developer">Developer</option>
                                        <option value="Tester">Tester</option>
                                        <option value="Support">Support</option>
                                        <option value="Intern">Intern</option>
                                        {userInfo.is_department_head && <option value="user">Standard User</option>}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Access Level</label>
                                    <select className="cyber-input" value={newUser.access_level} onChange={e => setNewUser({ ...newUser, access_level: e.target.value })}>
                                        <option value="Full Access">Full Access</option>
                                        <option value="Limited Access">Limited Access</option>
                                        <option value="Read Only">Read Only</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Department</label>
                                    <select
                                        className="cyber-input"
                                        value={newUser.department_id}
                                        onChange={e => setNewUser({ ...newUser, department_id: e.target.value })}
                                        disabled={userInfo.is_department_head} // Locked to own department
                                    >
                                        <option value="">Select Department</option>
                                        {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Designation Code</label>
                                    <select className="cyber-input" value={newUser.designation_code} onChange={e => setNewUser({ ...newUser, designation_code: e.target.value })}>
                                        <option value="Software Engineer">Software Engineer</option>
                                        <option value="QA Engineer">QA Engineer</option>
                                        <option value="System Admin">System Admin</option>
                                        <option value="Intern">Intern</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Account Type</label>
                                    <select className="cyber-input" value={newUser.account_type} onChange={e => setNewUser({ ...newUser, account_type: e.target.value })}>
                                        <option value="Permanent">Permanent</option>
                                        <option value="Contract">Contract</option>
                                        <option value="Temporary">Temporary</option>
                                        <option value="Intern">Intern</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Device ID</label>
                                    <input type="text" className="cyber-input" value={newUser.device_id} onChange={e => setNewUser({ ...newUser, device_id: e.target.value })} placeholder="Laptop-IT-001" />
                                </div>
                                <div className="form-group">
                                    <label>Hostname</label>
                                    <input type="text" className="cyber-input" value={newUser.hostname} onChange={e => setNewUser({ ...newUser, hostname: e.target.value })} placeholder="IT-LAP-EMP001" />
                                </div>
                                <div className="form-group">
                                    <label>Operating System</label>
                                    <select className="cyber-input" value={newUser.os_type} onChange={e => setNewUser({ ...newUser, os_type: e.target.value })}>
                                        <option value="Windows 10">Windows 10</option>
                                        <option value="Windows 11">Windows 11</option>
                                        <option value="Ubuntu">Linux (Ubuntu)</option>
                                        <option value="Kali">Linux (Kali)</option>
                                        <option value="macOS">macOS</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Mobile Number</label>
                                    <input type="text" className="cyber-input" value={newUser.mobile_number} onChange={e => setNewUser({ ...newUser, mobile_number: e.target.value })} placeholder="+91..." />
                                </div>
                                <div className="form-group">
                                    <label>Access Expiry (Permanent=Empty)</label>
                                    <input type="date" className="cyber-input" value={newUser.access_expiry} onChange={e => setNewUser({ ...newUser, access_expiry: e.target.value })} />
                                </div>
                                <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                                    <div style={{ display: 'flex', gap: '30px', alignItems: 'center' }}>
                                        <label className="checkbox-label">
                                            <input type="checkbox" checked={newUser.force_password_change} onChange={e => setNewUser({ ...newUser, force_password_change: e.target.checked })} /> Force password change
                                        </label>
                                        <label className="checkbox-label">
                                            <input type="checkbox" checked={newUser.is_department_head} onChange={e => setNewUser({ ...newUser, is_department_head: e.target.checked })} /> Assign as Dept Head
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div className="modal-actions">
                                <button type="button" className="btn-modern-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                                <button type="submit" className="btn-modern-primary">{isEditing ? 'Update Records' : 'Initialize Access'}</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
            {showOTPModal && (
                <OTPVerificationModal
                    isOpen={showOTPModal}
                    mobileNumber={otpTargetUser?.mobile_number}
                    onClose={() => setShowOTPModal(false)}
                    onVerified={async () => {
                        try {
                            const token = localStorage.getItem('token');
                            const updatePayload = { ...otpTargetUser };
                            delete updatePayload.username;
                            delete updatePayload.role;
                            delete updatePayload.email;
                            delete updatePayload.employee_id;
                            delete updatePayload.created_by;
                            delete updatePayload.access_level;
                            delete updatePayload.id; // Also remove ID if present in body

                            if (!updatePayload.password) delete updatePayload.password;
                            if (updatePayload.access_expiry === "") updatePayload.access_expiry = null;
                            if (updatePayload.password_expiry_days) updatePayload.password_expiry_days = parseInt(updatePayload.password_expiry_days);

                            await axios.put(`/users/${selectedUserId}`, updatePayload, {
                                headers: { Authorization: `Bearer ${token}` }
                            });
                            setNotification('User verified and updated successfully.');
                            fetchUsers();
                            setShowOTPModal(false);
                            setShowModal(false);
                            resetForm();
                        } catch (err) {
                            setNotification('Failed to update after verification.');
                        }
                    }}
                />
            )}
        </div>
    );
};

export default UserManagement;
