import React, { useState, useEffect } from 'react';
import axios from '../api';
import { Shield, Lock, Wifi, Monitor, Settings, Power, ChevronDown, ChevronUp, CheckCircle, Plus, X, Zap } from 'lucide-react';
import './Dashboard.css';

const SwitchToggle = ({ active }) => (
    <div style={{
        width: '36px',
        height: '20px',
        background: active ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255, 255, 255, 0.1)',
        borderRadius: '20px',
        position: 'relative',
        border: active ? '1px solid rgba(16, 185, 129, 0.5)' : '1px solid rgba(255, 255, 255, 0.1)'
    }}>
        <div style={{
            width: '14px',
            height: '14px',
            background: active ? '#10b981' : '#64748b',
            borderRadius: '50%',
            position: 'absolute',
            top: '2px',
            left: active ? '18px' : '2px',
            transition: 'all 0.3s ease',
            boxShadow: '0 2px 5px rgba(0,0,0,0.2)'
        }} />
    </div>
);

const Policies = () => {
    // Default structure for policies to ensure UI renders even before sync
    const defaultPolicies = {
        // Security Policies
        usb_lock: { name: 'USB Port Lock', category: 'Security', description: 'Prevents unauthorized USB device connections', enabled: false, applied_to: 0 },
        wallpaper_lock: { name: 'Wallpaper Lock', category: 'Security', description: 'Locks wallpaper to organization standard', enabled: false, applied_to: 0 },
        screen_lock: { name: 'Screen Lock', category: 'Security', description: 'Enforces automatic screen lock after inactivity', enabled: false, applied_to: 0 },
        password_policy: { name: 'Password Complexity', category: 'Security', description: 'Requires strong passwords (min 12 chars)', enabled: false, applied_to: 0 },
        encryption: { name: 'Disk Encryption', category: 'Security', description: 'Requires full disk encryption', enabled: false, applied_to: 0 },

        // Network Policies
        firewall: { name: 'Firewall Rules', category: 'Network', description: 'Enforces firewall configuration', enabled: false, applied_to: 0 },
        vpn_required: { name: 'VPN Requirement', category: 'Network', description: 'Requires VPN for remote access', enabled: false, applied_to: 0 },
        port_blocking: { name: 'Port Blocking', category: 'Network', description: 'Blocks dangerous network ports', enabled: false, applied_to: 0 },
        wifi_restrictions: { name: 'WiFi Restrictions', category: 'Network', description: 'Restricts to approved WiFi networks', enabled: false, applied_to: 0 },

        // Application Control
        app_whitelist: { name: 'Application Whitelist', category: 'Application', description: 'Only approved applications can run', enabled: false, applied_to: 0 },
        browser_restrictions: { name: 'Browser Security', category: 'Application', description: 'Enforces secure browser settings', enabled: false, applied_to: 0 },
        installation_control: { name: 'Install Control', category: 'Application', description: 'Prevents unauthorized software installation', enabled: false, applied_to: 0 },

        // Hardware Control
        camera_lock: { name: 'Camera Lock', category: 'Hardware', description: 'Disables camera functionality', enabled: false, applied_to: 0 },
        microphone_lock: { name: 'Microphone Lock', category: 'Hardware', description: 'Disables microphone functionality', enabled: false, applied_to: 0 },
        bluetooth_lock: { name: 'Bluetooth Lock', category: 'Hardware', description: 'Restricts Bluetooth connections', enabled: false, applied_to: 0 },
        external_drive_block: { name: 'External Drive Block', category: 'Hardware', description: 'Blocks external storage devices', enabled: false, applied_to: 0 },

        // System Policies
        auto_update: { name: 'Auto Updates', category: 'System', description: 'Automatically installs system updates', enabled: false, applied_to: 0 },
        patch_management: { name: 'Patch Management', category: 'System', description: 'Manages security patch deployment', enabled: false, applied_to: 0 },
        backup_policy: { name: 'Backup Policy', category: 'System', description: 'Enforces regular automated backups', enabled: false, applied_to: 0 },
        screen_recording_block: { name: 'Anti-Screen Record', category: 'System', description: 'Prevents screen recording software', enabled: false, applied_to: 0 },
    };

    const [policies, setPolicies] = useState({});
    const [loading, setLoading] = useState(true);
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const role = userInfo.role;
    const [expandedCategories, setExpandedCategories] = useState({
        Security: true, Network: true, Application: true, Hardware: true, System: true
    });

    const [departments, setDepartments] = useState([]);
    const [employees, setEmployees] = useState([]);
    const [selectedDept, setSelectedDept] = useState('');
    const [selectedEmployee, setSelectedEmployee] = useState('');

    // Settings Modal State
    const [showSettingsModal, setShowSettingsModal] = useState(false);
    const [selectedPolicyKey, setSelectedPolicyKey] = useState(null);
    const [selectedPolicyData, setSelectedPolicyData] = useState(null);
    const [configJson, setConfigJson] = useState('{}');

    const [isEnforcing, setIsEnforcing] = useState(false);

    useEffect(() => {
        fetchDepartments();
        if (role === 'admin') {
            fetchInitialPolicies();
        } else {
            fetchPolicies();
        }
    }, [role]);

    const fetchDepartments = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/departments/', { headers: { Authorization: `Bearer ${token}` } });
            setDepartments(res.data);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchEmployees = async (deptId) => {
        try {
            const token = localStorage.getItem('token');
            const res = await axios.get('/users/', {
                headers: { Authorization: `Bearer ${token}` },
                params: { department_id: deptId }
            });
            setEmployees(res.data);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchInitialPolicies = async () => {
        fetchPolicies();
    };

    const fetchPolicies = async () => {
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
                        config: p.config,
                        applied_to: p.applied_to_user_id ? 1 : 0,
                        lastModified: p.updated_at
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
                await axios.put(`/policies/${policy.id}`, {
                    enabled: newEnabled
                }, { headers: { Authorization: `Bearer ${token}` } });
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
            alert("Failed to update policy settings.");
        }
    };

    const openSettings = (key) => {
        const policy = policies[key];
        setSelectedPolicyKey(key);
        setSelectedPolicyData(policy);
        setConfigJson(JSON.stringify(policy.config || {}, null, 2));
        setShowSettingsModal(true);
    };

    const handlePropagate = async () => {
        try {
            const token = localStorage.getItem('token');
            await axios.post('/policies/propagate', {}, {
                headers: { Authorization: `Bearer ${token}` }
            });
            setIsEnforcing(true);
            setTimeout(() => setIsEnforcing(false), 5000); // Pulse for 5s
            alert("Policies propagated successfully to all online agents!");
        } catch (err) {
            console.error(err);
            alert("Failed to propagate policies.");
        }
    };

    const saveSettings = async () => {
        try {
            const config = JSON.parse(configJson);
            const token = localStorage.getItem('token');
            const policy = policies[selectedPolicyKey];

            if (policy.id) {
                await axios.put(`/policies/${policy.id}`, {
                    config: config
                }, { headers: { Authorization: `Bearer ${token}` } });
            } else {
                const res = await axios.post('/policies/', {
                    name: policy.name,
                    policy_type: selectedPolicyKey,
                    enabled: policy.enabled,
                    config: config,
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
                [selectedPolicyKey]: { ...prev[selectedPolicyKey], config: config }
            }));

            setShowSettingsModal(false);
        } catch (err) {
            alert("Invalid JSON configuration or Server Error");
        }
    };

    const toggleCategory = (category) => {
        setExpandedCategories(prev => ({ ...prev, [category]: !prev[category] }));
    };

    const handleDeptChange = (deptId) => {
        setSelectedDept(deptId);
        setSelectedEmployee('');
        if (deptId) {
            fetchEmployees(deptId);
        } else {
            setEmployees([]);
        }
    };

    useEffect(() => {
        if (role === 'admin') fetchPolicies();
    }, [selectedDept, selectedEmployee]);

    const categories = ['Security', 'Network', 'Application', 'Hardware', 'System'];
    const categoryIcons = {
        Security: <Shield size={20} />,
        Network: <Wifi size={20} />,
        Application: <Monitor size={20} />,
        Hardware: <Settings size={20} />,
        System: <Power size={20} />
    };

    const getPoliciesByCategory = (category) => {
        return Object.entries(policies).filter(([_, p]) => p.category === category);
    };

    const renderConfigEditor = () => {
        const isListType = ['app_whitelist', 'browser_restrictions', 'installation_control'].includes(selectedPolicyKey);

        return (
            <div className="form-group">
                <label>Configuration (JSON)</label>
                <textarea
                    className="cyber-input"
                    rows="6"
                    value={configJson}
                    onChange={(e) => setConfigJson(e.target.value)}
                    style={{ fontFamily: 'monospace', fontSize: '13px' }}
                />
                {isListType && (
                    <p className="subtitle" style={{ marginTop: '5px', fontSize: '0.8em' }}>
                        Tip: Use JSON array format like {"{\"blocked_items\": [\"item1\", \"item2\"]}"}
                    </p>
                )}
            </div>
        );
    };

    if (loading) return <div className="loading-state">Loading Policies...</div>;

    if (role !== 'admin') {
        const activePolicies = Object.entries(policies).filter(([_, p]) => p.enabled);
        return (
            <div className="dashboard-container fade-in">
                <header className="dashboard-header">
                    <div>
                        <h2><Shield className="icon-lg text-blue" /> My Security Policies</h2>
                        <p className="subtitle">Active security protocols enforcing your endpoint protection</p>
                    </div>
                    <div className="header-meta">
                        <span className="badge green pulse">
                            <CheckCircle size={14} style={{ marginRight: '6px' }} />
                            {activePolicies.length} Active Protocols
                        </span>
                    </div>
                </header>

                {activePolicies.length === 0 ? (
                    <div className="card full-width" style={{ textAlign: 'center', padding: '60px' }}>
                        <div style={{ background: 'rgba(255,255,255,0.05)', width: '80px', height: '80px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px' }}>
                            <Shield size={40} className="text-muted" />
                        </div>
                        <h3>No Active Policies</h3>
                        <p className="text-muted">Your endpoint currently has no restrictive policies applied.</p>
                    </div>
                ) : (
                    <div className="dashboard-grid">
                        {activePolicies.map(([key, p]) => (
                            <div key={key} className={`metric-card ${p.category === 'Security' ? 'primary' : p.category === 'Network' ? 'info' : 'warning'}`}>
                                <div className="metric-header" style={{ justifyContent: 'space-between', marginBottom: '15px' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                        <div className="icon-box" style={{ padding: '8px', borderRadius: '8px', background: 'var(--bg-acrylic)' }}>
                                            {categoryIcons[p.category] || <Shield size={18} />}
                                        </div>
                                        <span className="metric-label" style={{ fontSize: '0.75rem', opacity: 0.8 }}>{p.category}</span>
                                    </div>
                                    <SwitchToggle active={true} />
                                </div>
                                <h4 style={{ fontSize: '1.1rem', marginBottom: '8px', color: 'var(--text-primary)' }}>{p.name}</h4>
                                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '15px', minHeight: '40px' }}>
                                    {p.description}
                                </p>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: '#10b981' }}>
                                    <CheckCircle size={14} />
                                    <span style={{ fontWeight: '600', letterSpacing: '0.5px' }}>ENFORCED</span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        );
    }



    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><Shield className="icon-lg" /> Policy Management</h2>
                <div className="header-actions" style={{ display: 'flex', gap: '15px' }}>
                    <button className={`btn-modern-primary ${isEnforcing ? 'pulse' : ''}`} onClick={handlePropagate}>
                        <Zap size={14} /> PROPAGATE TO AGENTS
                    </button>
                    <div className="header-meta">
                        <span className="badge green">
                            {Object.values(policies).filter(p => p.enabled).length} / {Object.keys(policies).length} Active
                        </span>
                    </div>
                </div>
            </header>

            <div className="card full-width">
                <div className="policy-filter-flow" style={{ display: 'flex', gap: '20px', marginBottom: '20px', padding: '15px', background: 'rgba(255,255,255,0.03)', borderRadius: '12px' }}>
                    <div className="filter-group" style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Step 1: Select Department</label>
                        <select
                            className="form-input"
                            value={selectedDept}
                            onChange={(e) => handleDeptChange(e.target.value)}
                        >
                            <option value="">Global / All Departments</option>
                            {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                        </select>
                    </div>
                    <div className="filter-group" style={{ flex: 1 }}>
                        <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Step 2: Select Employee (Optional)</label>
                        <select
                            className="form-input"
                            value={selectedEmployee}
                            onChange={(e) => setSelectedEmployee(e.target.value)}
                            disabled={!selectedDept}
                        >
                            <option value="">Full Department Policy</option>
                            {employees.map(e => <option key={e.id} value={e.id}>{e.full_name || e.username}</option>)}
                        </select>
                    </div>
                </div>

                <div className="policy-summary text-center">
                    <h3>{selectedEmployee ? `Policies for ${employees.find(e => e.id === parseInt(selectedEmployee))?.full_name}` : selectedDept ? `Policies for Department: ${departments.find(d => d.id === parseInt(selectedDept))?.name}` : 'Enterprise-Wide Global Policies'}</h3>
                    <div className="stats-grid">
                        {categories.map(cat => {
                            const catPols = getPoliciesByCategory(cat);
                            const active = catPols.filter(([_, p]) => p.enabled).length;
                            return (
                                <div key={cat} className={`metric-box ${active > 0 ? 'green-border' : 'blue-border'}`}>
                                    <h4>{categoryIcons[cat]} {cat}</h4>
                                    <p>{active} / {catPols.length} Active</p>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>

            {categories.map(category => (
                <div key={category} className="card full-width policy-category">
                    <div className="category-header" onClick={() => toggleCategory(category)}>
                        <h3>{categoryIcons[category]} <span>{category} Policies</span></h3>
                        <button className="expand-btn">
                            {expandedCategories[category] ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                        </button>
                    </div>

                    {expandedCategories[category] && (
                        <div className="policy-list">
                            {getPoliciesByCategory(category).map(([key, policy]) => (
                                <div key={key} className="policy-item">
                                    <div className="policy-info">
                                        <div className="policy-header-row">
                                            <h4>{policy.name}</h4>
                                            <div className="policy-controls">
                                                <label className="toggle-switch-modern">
                                                    <input
                                                        type="checkbox"
                                                        checked={policy.enabled}
                                                        onChange={() => togglePolicy(key)}
                                                    />
                                                    <span className="toggle-slider"></span>
                                                </label>
                                                <button
                                                    className="settings-icon-btn highlight-hover"
                                                    onClick={() => openSettings(key)}
                                                    title="Configure Policy"
                                                    style={{ border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)' }}
                                                >
                                                    <Settings size={18} className="text-blue" />
                                                </button>
                                            </div>
                                        </div>
                                        <p className="policy-description">{policy.description}</p>
                                        <div className="policy-meta">
                                            <span className={`badge ${policy.enabled ? 'badge-success' : 'badge-danger'} ${policy.enabled && isEnforcing ? 'pulse' : ''}`} style={{ fontWeight: '700' }}>
                                                {policy.enabled ? (isEnforcing ? 'ENFORCING' : 'ACTIVE') : 'OFF'}
                                            </span>
                                            {policy.lastModified && (
                                                <span className="policy-stat">Modified: {new Date(policy.lastModified).toLocaleDateString()}</span>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            ))}

            {showSettingsModal && (
                <div className="modal-overlay" onClick={() => setShowSettingsModal(false)}>
                    <div className="modal-content card" onClick={(e) => e.stopPropagation()}>
                        <h3>Configure {selectedPolicyData?.name}</h3>
                        <div className="form-group">
                            <label>Status</label>
                            <div className="status-indicator">
                                <span className={`badge ${selectedPolicyData?.enabled ? 'green' : 'red'}`}>
                                    {selectedPolicyData?.enabled ? 'Enabled' : 'Disabled'}
                                </span>
                            </div>
                        </div>
                        {renderConfigEditor()}
                        <div className="form-buttons">
                            <button className="cancel-btn" onClick={() => setShowSettingsModal(false)}>Cancel</button>
                            <button className="action-btn" onClick={saveSettings}>Save Configuration</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Policies;
