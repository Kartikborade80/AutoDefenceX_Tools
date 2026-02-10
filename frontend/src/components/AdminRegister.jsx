import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../api';
import { Building, User, Mail, Phone, Lock, ChevronLeft, ShieldCheck } from 'lucide-react';
import './Login.css';

const AdminRegister = () => {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        confirmPassword: '',
        full_name: '',
        email: '',
        company_name: '',
        company_address: '',
        company_domain: '',
        phone: ''
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        setLoading(true);
        try {
            console.log("Submitting Admin Registration:", formData);
            const { confirmPassword, ...registerData } = formData;
            const res = await axios.post('/users/register-admin', registerData);
            console.log("Registration Success:", res.data);
            alert('Admin registration successful! You can now login.');
            navigate('/login');
        } catch (err) {
            console.error("Registration Error:", err);
            console.error("Error Response:", err.response);
            if (err.response && err.response.status === 422) {
                console.error("Validation Details:", err.response.data.detail);
                setError(`Validation Error: ${JSON.stringify(err.response.data.detail)}`);
            } else {
                setError(err.response?.data?.detail || 'Registration failed. Username may exist.');
            }
        } finally {
            setLoading(false);
        }
    };

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    return (
        <div className="login-container">
            <div className="center-box slide-up admin-reg">
                <header className="auth-header">
                    <ShieldCheck size={40} className="glow-icon" />
                    <h2 className="glow-text">Establish Admin Domain</h2>
                    <p className="subtitle">Register your organization for enterprise protection</p>
                </header>

                <form onSubmit={handleSubmit} className="login-form">
                    <div className="form-section">
                        <h4><Building size={16} /> Organization Details</h4>
                        <div className="input-group">
                            <input
                                name="company_name"
                                type="text"
                                placeholder="Organization Name *"
                                value={formData.company_name}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                        </div>
                        <div className="input-group">
                            <input
                                name="company_address"
                                type="text"
                                placeholder="Organization Address"
                                value={formData.company_address}
                                onChange={handleChange}
                                className="cyber-input"
                            />
                        </div>
                        <div className="input-group">
                            <input
                                name="company_domain"
                                type="text"
                                placeholder="Company Email Domain (e.g., techcorp.com)"
                                value={formData.company_domain}
                                onChange={handleChange}
                                className="cyber-input"
                            />
                            <small style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '5px' }}>Used for auto-generating employee emails</small>
                        </div>
                    </div>

                    <div className="form-section mt-10">
                        <h4><User size={16} /> Administrator Profile</h4>
                        <div className="input-row">
                            <input
                                name="full_name"
                                type="text"
                                placeholder="Full Name *"
                                value={formData.full_name}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                            <input
                                name="phone"
                                type="text"
                                placeholder="Contact Number"
                                value={formData.phone}
                                onChange={handleChange}
                                className="cyber-input"
                            />
                        </div>
                        <div className="input-group">
                            <input
                                name="email"
                                type="email"
                                placeholder="Admin Email Address *"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                        </div>
                        <div className="input-row">
                            <input
                                name="username"
                                type="text"
                                placeholder="Admin Username *"
                                value={formData.username}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                            <input
                                name="password"
                                type="password"
                                placeholder="Create Password *"
                                value={formData.password}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                        </div>
                        <div className="input-group">
                            <input
                                name="confirmPassword"
                                type="password"
                                placeholder="Confirm Password *"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required
                                className="cyber-input"
                            />
                        </div>
                    </div>

                    <button type="submit" className="login-btn mt-20" disabled={loading}>
                        {loading ? 'Establish Domain...' : 'Establish Domain Control'}
                    </button>
                </form>

                {error && <p className="error-msg">{error}</p>}

                <button className="back-link" onClick={() => navigate('/login')}>
                    <ChevronLeft size={16} /> Back to Login
                </button>
            </div>
        </div>
    );
};

export default AdminRegister;
