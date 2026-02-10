import React, { useEffect, useState } from 'react';
import axios from '../api';
import './Dashboard.css';
import { User, Smartphone, Briefcase, Hash, Shield, Monitor } from 'lucide-react';
import './ProfileRefinements.css';

const About = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchUser = async () => {
            try {
                setLoading(true);
                const token = localStorage.getItem('token');
                const res = await axios.get('/users/me', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setUser(res.data);
                setError(null);
            } catch (err) {
                console.error("Failed to fetch user details", err);
                setError(err.response?.status === 401
                    ? "Session expired. Please log in again."
                    : "Failed to load profile. Please try again later.");
            } finally {
                setLoading(false);
            }
        };
        fetchUser();
    }, []);

    if (loading) return <div className="loading">Loading Profile...</div>;

    if (error) {
        return (
            <div className="dashboard-container fade-in">
                <div className="card full-width" style={{ textAlign: 'center', padding: '3rem' }}>
                    <User size={48} style={{ color: 'var(--danger)', marginBottom: '1rem' }} />
                    <h3 style={{ color: 'var(--danger)' }}>Error Loading Profile</h3>
                    <p style={{ color: 'var(--text-secondary)' }}>{error}</p>
                </div>
            </div>
        );
    }

    if (!user) return <div className="loading">No profile data available</div>;

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><User className="icon-lg" /> Employee Profile</h2>
                <div className="header-meta">
                    <span className="badge blue">ACTIVE EMPLOYEE</span>
                </div>
            </header>

            <div className="grid-container">
                <div className="card profile-main-card">
                    <div className="profile-hero">
                        <div className="avatar-circle-large">
                            {user.full_name ? user.full_name.charAt(0) : user.username.charAt(0)}
                        </div>
                        <div className="profile-identity">
                            <h3>{user.full_name || user.username}</h3>
                            <div className="badge badge-user">{user.job_title || 'Organization Member'}</div>
                        </div>
                    </div>

                    <div className="profile-details-grid">
                        <div className="profile-detail-box">
                            <div className="detail-label"><Hash size={14} /> Employee ID</div>
                            <div className="detail-value text-primary">{user.employee_id || 'TM-GEN-001'}</div>
                        </div>
                        <div className="profile-detail-box">
                            <div className="detail-label"><Briefcase size={14} /> Official Role</div>
                            <div className="detail-value text-primary">{user.role.toUpperCase()}</div>
                        </div>
                        <div className="profile-detail-box">
                            <div className="detail-label"><Smartphone size={14} /> Contact</div>
                            <div className="detail-value text-primary">{user.mobile_number || 'N/A'}</div>
                        </div>
                        <div className="profile-detail-box">
                            <div className="detail-label"><Monitor size={14} /> Assigned Asset</div>
                            <div className="detail-value text-primary mono">{user.asset_id || 'ASSET-IDX-92'}</div>
                        </div>
                    </div>
                </div>

                <div className="card profile-policies-card">
                    <div className="card-header">
                        <h3><Shield size={20} className="text-primary" /> Active Access Control Policies</h3>
                        <span className="badge badge-success">Enforced</span>
                    </div>
                    <div className="profile-policy-grid">
                        <div className={`policy-highlight-box ${user.access_control?.usb_block ? 'locked' : 'unlocked'}`}>
                            <div className="flex-between">
                                <span className="policy-label">USB Port Access</span>
                                <span className={`badge ${user.access_control?.usb_block ? 'badge-danger' : 'badge-success'}`}>
                                    {user.access_control?.usb_block ? 'BLOCKED' : 'ALLOWED'}
                                </span>
                            </div>
                            <p className="policy-note">
                                {user.access_control?.usb_block
                                    ? "External storage devices are restricted by system policy."
                                    : "External storage devices can be mounted to this endpoint."}
                            </p>
                        </div>
                        <div className={`policy-highlight-box ${user.access_control?.wallpaper_lock ? 'locked' : 'unlocked'}`}>
                            <div className="flex-between">
                                <span className="policy-label">Wallpaper Customization</span>
                                <span className={`badge ${user.access_control?.wallpaper_lock ? 'badge-danger' : 'badge-success'}`}>
                                    {user.access_control?.wallpaper_lock ? 'LOCKED' : 'ALLOWED'}
                                </span>
                            </div>
                            <p className="policy-note">
                                {user.access_control?.wallpaper_lock
                                    ? "Desktop background is locked to organization standards."
                                    : "You have permission to modify your desktop background."}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default About;
