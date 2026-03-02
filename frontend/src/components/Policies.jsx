import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Shield, Lock, Wifi, Monitor, Settings, Power, ChevronDown, ChevronUp, CheckCircle, Plus, X, Zap, Sliders, Users, Globe, Layout as LayoutIcon, Cpu, Activity } from 'lucide-react';
import './Dashboard.css';

const SwitchToggle = ({ enabled, onChange }) => (
    <label className="policy-toggle">
        <input type="checkbox" checked={enabled} onChange={onChange} />
        <span className="policy-slider"></span>
    </label>
);

const Policies = () => {
    const defaultPolicies = {
        usb_lock: { name: 'USB Port Lock', category: 'Security', description: 'Prevents unauthorized USB device connections', enabled: false },
        wallpaper_lock: { name: 'Wallpaper Lock', category: 'Security', description: 'Locks wallpaper to organization standard', enabled: false },
        screen_lock: { name: 'Screen Lock', category: 'Security', description: 'Enforces automatic screen lock after inactivity', enabled: false },
        password_policy: { name: 'Password Complexity', category: 'Security', description: 'Requires strong passwords (min 12 chars)', enabled: false },
        encryption: { name: 'Disk Encryption', category: 'Security', description: 'Requires full disk encryption', enabled: false },
        firewall: { name: 'Firewall Rules', category: 'Network', description: 'Enforces firewall configuration', enabled: false },
        vpn_required: { name: 'VPN Requirement', category: 'Network', description: 'Requires VPN for remote access', enabled: false },
        port_blocking: { name: 'Port Blocking', category: 'Network', description: 'Blocks dangerous network ports', enabled: false },
        wifi_restrictions: { name: 'WiFi Restrictions', category: 'Network', description: 'Restricts to approved WiFi networks', enabled: false },
        app_whitelist: { name: 'Application Whitelist', category: 'Application', description: 'Only approved applications can run', enabled: false },
        browser_restrictions: { name: 'Browser Security', category: 'Application', description: 'Enforces secure browser settings', enabled: false },
        installation_control: { name: 'Install Control', category: 'Application', description: 'Prevents unauthorized software installation', enabled: false },
        camera_lock: { name: 'Camera Lock', category: 'Hardware', description: 'Disables camera functionality', enabled: false },
        microphone_lock: { name: 'Microphone Lock', category: 'Hardware', description: 'Disables microphone functionality', enabled: false },
        bluetooth_lock: { name: 'Bluetooth Lock', category: 'Hardware', description: 'Restricts Bluetooth connections', enabled: false },
        external_drive_block: { name: 'External Drive Block', category: 'Hardware', description: 'Blocks external storage devices', enabled: false },
        auto_update: { name: 'Auto Updates', category: 'System', description: 'Automatically installs system updates', enabled: false },
        patch_management: { name: 'Patch Management', category: 'System', description: 'Manages security patch deployment', enabled: false },
        backup_policy: { name: 'Backup Policy', category: 'System', description: 'Enforces regular automated backups', enabled: false },
        screen_recording_block: { name: 'Anti-Screen Record', category: 'System', description: 'Prevents screen recording software', enabled: false },
    };

    const [policies, setPolicies] = useState({});
    const [loading, setLoading] = useState(true);
    const [activeCategory, setActiveCategory] = useState('Security');
    const [departments, setDepartments] = useState([]);
    const [employees, setEmployees] = useState([]);
    const [selectedDept, setSelectedDept] = useState('');
    const [selectedEmployee, setSelectedEmployee] = useState('');
    const [isEnforcing, setIsEnforcing] = useState(false);
    const [showSettingsModal, setShowSettingsModal] = useState(false);
    const [selectedPolicyKey, setSelectedPolicyKey] = useState(null);
    const [configJson, setConfigJson] = useState('{}');

    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const role = userInfo.role;

    useEffect(() => {
        fetchDepartments();
        fetchPolicies();
    }, []);

    useEffect(() => {
        if (role === 'admin') fetchPolicies();
    }, [selectedDept, selectedEmployee]);

    const fetchDepartments = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/departments/', { headers: { Authorization: `Bearer ${token}` } });
            setDepartments(res.data);
        } catch (err) { console.error(err); }
    };

    const fetchEmployees = async (deptId) => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/users/', {
                headers: { Authorization: `Bearer ${token}` },
                params: { department_id: deptId }
            });
            setEmployees(res.data);
        } catch (err) { console.error(err); }
    };

    const fetchPolicies = async () => {
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            const params = {};
            if (selectedEmployee) params.user_id = selectedEmployee;
            else if (selectedDept) params.department_id = selectedDept;

            const res = await axios.get('/policies/', {
                headers: { Authorization: `Bearer ${token}` },
                params
            });

            const mergedPolicies = { ...defaultPolicies };
            res.data.forEach(p => {
                if (mergedPolicies[p.policy_type]) {
                    mergedPolicies[p.policy_type] = {
                        ...mergedPolicies[p.policy_type],
                        id: p.id,
                        enabled: p.enabled,
                        config: p.config
                    };
                }
            });
            setPolicies(mergedPolicies);
        } catch (err) {
            console.error("Failed to fetch policies", err);
            setPolicies(defaultPolicies);
        } finally {
            setLoading(false);
        }
    };

    const togglePolicy = async (key) => {
        const policy = policies[key];
        const newEnabled = !policy.enabled;

        setPolicies(prev => ({
            ...prev,
            [key]: { ...prev[key], enabled: newEnabled }
        }));

        try {
            const token = localStorage.getItem('token');
            if (policy.id) {
                await axios.put(`/policies/${policy.id}`, { enabled: newEnabled }, { headers: { Authorization: `Bearer ${token}` } });
            } else {
                const res = await axios.post('/policies/', {
                    name: policy.name,
                    policy_type: key,
                    enabled: newEnabled,
                    config: policy.config || {},
                    applied_to_user_id: selectedEmployee ? parseInt(selectedEmployee) : null,
                    department_id: selectedDept ? parseInt(selectedDept) : null
                }, { headers: { Authorization: `Bearer ${token}` } });

                setPolicies(prev => ({
                    ...prev,
                    [key]: { ...prev[key], id: res.data.id }
                }));
            }
        } catch (err) {
            setPolicies(prev => ({
                ...prev,
                [key]: { ...prev[key], enabled: !newEnabled }
            }));
        }
    };

    const handlePropagate = async () => {
        try {
            const token = localStorage.getItem('token');
            await axios.post('/policies/propagate', {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setIsEnforcing(true);
            setTimeout(() => setIsEnforcing(false), 5000);
        } catch (err) {
            console.error(err);
        }
    };

    const openSettings = (key) => {
        const policy = policies[key];
        setSelectedPolicyKey(key);
        setConfigJson(JSON.stringify(policy.config || {}, null, 2));
        setShowSettingsModal(true);
    };

    const saveSettings = async () => {
        try {
            const config = JSON.parse(configJson);
            const token = localStorage.getItem('token');
            const policy = policies[selectedPolicyKey];

            if (policy.id) {
                await axios.put(`/policies/${policy.id}`, { config }, { headers: { Authorization: `Bearer ${token}` } });
            } else {
                const res = await axios.post('/policies/', {
                    name: policy.name,
                    policy_type: selectedPolicyKey,
                    enabled: policy.enabled,
                    config,
                    applied_to_user_id: selectedEmployee ? parseInt(selectedEmployee) : null,
                    department_id: selectedDept ? parseInt(selectedDept) : null
                }, { headers: { Authorization: `Bearer ${token}` } });

                setPolicies(prev => ({
                    ...prev,
                    [selectedPolicyKey]: { ...prev[selectedPolicyKey], id: res.data.id }
                }));
            }

            setPolicies(prev => ({
                ...prev,
                [selectedPolicyKey]: { ...prev[selectedPolicyKey], config }
            }));
            setShowSettingsModal(false);
        } catch (err) { alert("Invalid JSON"); }
    };

    const handleDeptChange = (deptId) => {
        setSelectedDept(deptId);
        setSelectedEmployee('');
        if (deptId) fetchEmployees(deptId);
        else setEmployees([]);
    };

    const categories = ['Security', 'Network', 'Application', 'Hardware', 'System'];
    const categoryIcons = {
        Security: <Shield size={18} />,
        Network: <Wifi size={18} />,
        Application: <LayoutIcon size={18} />,
        Hardware: <Cpu size={18} />,
        System: <Settings size={18} />
    };

    const policyIcons = {
        usb_lock: <Lock size={22} />,
        wallpaper_lock: <Monitor size={22} />,
        screen_lock: <Power size={22} />,
        password_policy: <Shield size={22} />,
        encryption: <Zap size={22} />,
        firewall: <Shield size={22} />,
        vpn_required: <Globe size={22} />,
        port_blocking: <Lock size={22} />,
        wifi_restrictions: <Wifi size={22} />,
        app_whitelist: <Monitor size={22} />,
        browser_restrictions: <Globe size={22} />,
        installation_control: <Settings size={22} />,
        camera_lock: <Monitor size={22} />,
        microphone_lock: <Cpu size={22} />,
        bluetooth_lock: <Wifi size={22} />,
        external_drive_block: <Lock size={22} />,
        auto_update: <Zap size={22} />,
        patch_management: <Shield size={22} />,
        backup_policy: <Cpu size={22} />,
        screen_recording_block: <Monitor size={22} />,
    };

    const filteredPolicies = Object.entries(policies).filter(([_, p]) => p.category === activeCategory);

    if (loading && Object.keys(policies).length === 0) {
        return <div className="loading-state-container"><div className="loading-spinner"></div><p className="loading-text">Synchronizing Policies...</p></div>;
    }

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <div>
                    <h2><Shield className="icon-lg text-blue" /> Policy Management</h2>
                    <p className="subtitle">Enforce security protocols across all endpoints and users</p>
                </div>
                <div className="header-actions" style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
                    {role === 'admin' && (
                        <button className={`btn-modern-primary ${isEnforcing ? 'pulse' : ''}`} onClick={handlePropagate}>
                            <Zap size={16} /> PROPAGATE CHANGES
                        </button>
                    )}
                    <div className="header-meta">
                        <span className="badge green pulse">
                            <Activity size={12} style={{ marginRight: '6px' }} />
                            {Object.values(policies).filter(p => p.enabled).length} ACTIVE
                        </span>
                    </div>
                </div>
            </header>

            {role === 'admin' && (
                <div className="card full-width glass-panel" style={{ padding: '20px', marginBottom: '30px' }}>
                    <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                        <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)' }}>DEPT SCOPE</label>
                            <select className="cyber-input" value={selectedDept} onChange={(e) => handleDeptChange(e.target.value)} style={{ marginBottom: 0 }}>
                                <option value="">Enterprise Wide (Global)</option>
                                {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                            </select>
                        </div>
                        <div style={{ flex: 1 }}>
                            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.8rem', fontWeight: '600', color: 'var(--text-secondary)' }}>USER SCOPE</label>
                            <select className="cyber-input" value={selectedEmployee} onChange={(e) => setSelectedEmployee(e.target.value)} disabled={!selectedDept} style={{ marginBottom: 0 }}>
                                <option value="">Whole Department</option>
                                {employees.map(e => <option key={e.id} value={e.id}>{e.full_name || e.username}</option>)}
                            </select>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '0 20px', borderLeft: '1px solid var(--border-glass)' }}>
                            <Users size={20} className="text-blue" />
                            <div>
                                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>TARGET ENTITY</div>
                                <div style={{ fontSize: '0.9rem', fontWeight: '600' }}>
                                    {selectedEmployee ? 'Individual User' : selectedDept ? 'Department' : 'Global Fleet'}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <nav className="category-nav">
                {categories.map(cat => (
                    <button
                        key={cat}
                        className={`category-tab ${activeCategory === cat ? 'active' : ''}`}
                        onClick={() => setActiveCategory(cat)}
                    >
                        {categoryIcons[cat]} {cat}
                    </button>
                ))}
            </nav>

            <div className="policy-grid">
                {filteredPolicies.map(([key, policy]) => (
                    <div key={key} className={`policy-card-modern ${policy.enabled ? 'active' : 'inactive'}`}>
                        <div>
                            <div className="policy-card-header">
                                <div className="policy-icon-wrapper">
                                    {policyIcons[key] || <Shield size={22} />}
                                </div>
                                <SwitchToggle
                                    enabled={policy.enabled}
                                    onChange={() => togglePolicy(key)}
                                />
                            </div>
                            <div className="policy-content">
                                <h4>{policy.name}</h4>
                                <p>{policy.description}</p>
                            </div>
                        </div>
                        <div className="policy-footer">
                            <div className="policy-status-indicator">
                                <span className={`policy-status-dot ${policy.enabled ? 'active' : 'inactive'}`}></span>
                                <span style={{ color: policy.enabled ? '#10b981' : 'var(--text-secondary)' }}>
                                    {policy.enabled ? 'Enforced' : 'Stopped'}
                                </span>
                            </div>
                            <button className="settings-icon-btn highlight-hover" onClick={() => openSettings(key)} title="Technical Config">
                                <Sliders size={16} />
                            </button>
                        </div>
                    </div>
                ))}
            </div>

            {showSettingsModal && (
                <div className="modal-overlay" onClick={() => setShowSettingsModal(false)}>
                    <div className="modal-content card slide-up" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '500px' }}>
                        <div className="modal-header">
                            <h3><Sliders size={20} className="text-blue" /> Policy Configuration</h3>
                            <button className="btn-icon" onClick={() => setShowSettingsModal(false)}><X size={20} /></button>
                        </div>
                        <div className="form-group">
                            <label style={{ display: 'block', marginBottom: '10px', fontSize: '0.9rem' }}>Advanced Paramaters (JSON)</label>
                            <textarea
                                className="cyber-input"
                                rows="8"
                                value={configJson}
                                onChange={(e) => setConfigJson(e.target.value)}
                                style={{ fontFamily: 'monospace', fontSize: '13px', background: '#000' }}
                            />
                            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
                                Modify raw engine parameters for this policy. Incorrect JSON will prevent saving.
                            </p>
                        </div>
                        <div className="modal-actions">
                            <button className="btn-cancel" onClick={() => setShowSettingsModal(false)}>Discard</button>
                            <button className="action-btn" onClick={saveSettings}>Apply Settings</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Policies;
