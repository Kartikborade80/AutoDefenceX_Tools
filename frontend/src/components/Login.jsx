import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from '../api';
import { Eye, EyeOff, LogIn, Lock, XCircle, User, Shield } from 'lucide-react';
import './Login.css';
import PasswordChangeModal from './PasswordChangeModal';

const Login = ({ onLogin }) => {
    const navigate = useNavigate();
    const [showWelcome, setShowWelcome] = useState(true); // New: Welcome screen state
    const [role, setRole] = useState(null); // 'user', 'admin', 'normal'
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [organizationName, setOrganizationName] = useState('AutoDefenceX');
    const [otpRequired, setOtpRequired] = useState(false);
    const [loginOTP, setLoginOTP] = useState('');
    const [maskedPhone, setMaskedPhone] = useState('');

    // Live company name display
    const [companyName, setCompanyName] = useState('');
    const [userName, setUserName] = useState('');
    const [departmentName, setDepartmentName] = useState('');
    const [riskScore, setRiskScore] = useState(null);
    const [usernameValid, setUsernameValid] = useState(null);
    const [checkingUsername, setCheckingUsername] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [loginSuccess, setLoginSuccess] = useState(false);

    // Password Change Modal State
    const [showPasswordChange, setShowPasswordChange] = useState(false);
    const [passwordChangeUserInfo, setPasswordChangeUserInfo] = useState(null);

    // Registration State
    const [showRegister, setShowRegister] = useState(false);
    const [regStep, setRegStep] = useState(1); // 1: Info, 2: OTP
    const [regData, setRegData] = useState({ username: '', password: '', full_name: '', mobile_number: '' });
    const [regOTP, setRegOTP] = useState('');
    const [regMsg, setRegMsg] = useState('');
    const [loadingReg, setLoadingReg] = useState(false);

    // Forgot Password State
    const [showForgot, setShowForgot] = useState(false);
    const [forgotStep, setForgotStep] = useState(1); // 1: username, 2: otp & new password
    const [forgotUsername, setForgotUsername] = useState('');
    const [forgotOTP, setForgotOTP] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [forgotMsg, setForgotMsg] = useState('');
    const [forgotError, setForgotError] = useState('');
    const [loadingForgot, setLoadingForgot] = useState(false);

    // Motivational Quotes for Endpoint Users
    const motivationalQuotes = [
        { text: "Your hard work is the shield that protects our digital frontier. Keep up the great work!", author: "Security Team" },
        { text: "Excellence is not a skill, it's an attitude. Your vigilance makes us stronger.", author: "Leadership" },
        { text: "The only way to do great work is to love what you do. Stay motivated!", author: "Steve Jobs" },
        { text: "Security is a team sport. Thank you for being a vital player!", author: "AutoDefenceX" },
        { text: "Every minor check today prevents a major breach tomorrow. Stay sharp!", author: "CISO" },
        { text: "Innovation distinguishes between a leader and a follower. Lead the way!", author: "IT Hub" },
        { text: "Precision and patience are the keys to a secure environment.", author: "Security Analyst" },
        { text: "Success is the sum of small efforts, repeated day in and day out.", author: "Robert Collier" }
    ];

    // Get daily quote based on current date
    const getDailyQuote = () => {
        const today = new Date();
        const index = (today.getFullYear() + today.getMonth() + today.getDate()) % motivationalQuotes.length;
        return motivationalQuotes[index];
    };

    const dailyQuote = getDailyQuote();

    // Fetch organization name from config or use default
    useEffect(() => {
        // Try to get organization name from environment or config
        // For now, using a default that can be configured
        const orgName = import.meta.env.VITE_ORG_NAME || 'AutoDefenceX';
        setOrganizationName(orgName);
    }, []);

    const handleUsernameChange = async (value) => {
        setUsername(value);
        setCompanyName('');
        setUserName('');
        setDepartmentName('');
        setRiskScore(null);
        setUsernameValid(null);

        if (value.length >= 3) {
            setCheckingUsername(true);
            try {
                const response = await axios.get(`/organizations/by-username/${value}`);
                if (response.data.exists) {
                    setCompanyName(response.data.organization_name);
                    setUserName(response.data.full_name);
                    setDepartmentName(response.data.department_name);
                    setRiskScore(response.data.risk_score);
                    setUsernameValid(true);
                } else {
                    setCompanyName('');
                    setUserName('');
                    setDepartmentName('');
                    setRiskScore(null);
                    setUsernameValid(false);
                }
            } catch (err) {
                setCompanyName('');
                setUserName('');
                setDepartmentName('');
                setRiskScore(null);
                setUsernameValid(null);
            } finally {
                setCheckingUsername(false);
            }
        }
    };

    const handleForgotPassword = async (e) => {
        if (e) e.preventDefault();
        setForgotError('');
        setForgotMsg('');
        setLoadingForgot(true);

        try {
            if (forgotStep === 1) {
                const response = await axios.post('/otp/forgot-password', { username: forgotUsername });
                setForgotMsg(response.data.message);
                setForgotStep(2);
            } else {
                const response = await axios.post('/otp/reset-password', {
                    username: forgotUsername,
                    otp_code: forgotOTP,
                    new_password: newPassword
                });
                setForgotMsg(response.data.message);
                setTimeout(() => {
                    setShowForgot(false);
                    setForgotStep(1);
                    setForgotUsername('');
                    setForgotOTP('');
                    setNewPassword('');
                }, 3000);
            }
        } catch (err) {
            setForgotError(err.response?.data?.detail || "An error occurred");
        } finally {
            setLoadingForgot(false);
        }
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);

        try {
            const params = new URLSearchParams();
            params.append('username', username);
            params.append('password', password);
            if (loginOTP) params.append('otp', loginOTP);

            const response = await axios.post('/auth/token', params, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            if (response.data.otp_required) {
                setOtpRequired(true);
                setMaskedPhone(response.data.phone_masked);
                setIsLoading(false);
                return;
            }

            const { access_token, user_info } = response.data;

            // Validate token exists and is not empty
            if (!access_token || access_token === '') {
                setError('Authentication failed - no token received');
                setIsLoading(false);
                return;
            }

            localStorage.setItem('token', access_token);

            // Store comprehensive user info and login time
            const loginTime = new Date().toISOString();
            localStorage.setItem('user_info', JSON.stringify(user_info));
            localStorage.setItem('login_time', loginTime);

            const payload = JSON.parse(atob(access_token.split('.')[1]));

            // Role Verification
            if (role === 'admin' && payload.role !== 'admin') {
                setError('Access Denied: You are not an Admin.');
                setIsLoading(false);
                return;
            }

            // Trigger success animation
            setLoginSuccess(true);
            setIsLoading(false);

            // Navigate after brief delay to show success animation
            setTimeout(() => {
                onLogin(payload.role);
            }, 800);

        } catch (err) {
            console.error(err);
            let detail = err.response?.data?.detail || 'Invalid Credentials or Server Error';
            if (typeof detail === 'object') {
                detail = JSON.stringify(detail);
            }
            setError(detail);
            setIsLoading(false);
        }
    };

    const handleRegisterInitiate = async (e) => {
        e.preventDefault();
        setRegMsg('');
        setLoadingReg(true);
        try {
            // First send OTP to the number
            const response = await axios.post('/otp/send', { phone_number: regData.mobile_number });
            if (response.data.success) {
                setRegStep(2);
                setRegMsg('Please enter the OTP sent to your mobile.');
            }
        } catch (err) {
            setRegMsg(err.response?.data?.detail || 'Failed to send verification OTP.');
        } finally {
            setLoadingReg(false);
        }
    };

    const handleRegisterVerify = async (e) => {
        e.preventDefault();
        setRegMsg('');
        setLoadingReg(true);
        try {
            // Verify OTP first
            const verifyResp = await axios.post('/otp/verify', {
                phone_number: regData.mobile_number,
                otp_code: regOTP
            });

            if (verifyResp.data.success) {
                // If verified, proceed to create user
                await axios.post('/users/register-public', {
                    ...regData
                });
                setRegMsg('Registration Successful! Please Login.');
                setTimeout(() => {
                    setShowRegister(false);
                    setRegStep(1);
                    setRegData({ username: '', password: '', full_name: '', mobile_number: '' });
                    setRegOTP('');
                }, 3000);
            }
        } catch (err) {
            setRegMsg(err.response?.data?.detail || 'Verification or Registration failed.');
        } finally {
            setLoadingReg(false);
        }
    };

    if (showRegister) {
        return (
            <div className="login-container">
                <div className="center-box slide-up">
                    <h2 className="glow-text">Personal Account Registration</h2>

                    {regStep === 1 ? (
                        <form onSubmit={handleRegisterInitiate} className="login-form">
                            <input type="text" placeholder="Full Name" className="cyber-input" required
                                value={regData.full_name} onChange={e => setRegData({ ...regData, full_name: e.target.value })} />
                            <input type="text" placeholder="Mobile Number (e.g. 8010374800)" className="cyber-input" required
                                value={regData.mobile_number} onChange={e => setRegData({ ...regData, mobile_number: e.target.value })} />
                            <input type="text" placeholder="Username" className="cyber-input" required
                                value={regData.username} onChange={e => setRegData({ ...regData, username: e.target.value })} />
                            <input type="password" placeholder="Password" className="cyber-input" required
                                value={regData.password} onChange={e => setRegData({ ...regData, password: e.target.value })} />

                            <button type="submit" className="login-btn" disabled={loadingReg}>
                                {loadingReg ? 'Sending OTP...' : 'Send Verification OTP'}
                            </button>
                        </form>
                    ) : (
                        <form onSubmit={handleRegisterVerify} className="login-form">
                            <p className="subtitle">Verifying {regData.mobile_number}</p>
                            <input type="text" placeholder="Enter 6-digit OTP" className="cyber-input" required
                                value={regOTP} onChange={e => setRegOTP(e.target.value)} />

                            <div className="button-group">
                                <button type="submit" className="login-btn" disabled={loadingReg}>
                                    {loadingReg ? 'Verifying...' : 'Verify & Register'}
                                </button>
                                <button type="button" className="text-btn" onClick={() => setRegStep(1)}>
                                    Change Number
                                </button>
                            </div>
                        </form>
                    )}

                    {regMsg && <p className={`error-msg ${regMsg.includes('Successful') ? 'text-green' : ''}`}>{regMsg}</p>}

                    <button className="back-link" onClick={() => {
                        setShowRegister(false);
                        setRegStep(1);
                        setRegMsg('');
                    }}>
                        &larr; Back to Login
                    </button>
                </div>
            </div>
        );
    }

    // Welcome Screen - First page load
    if (showWelcome) {
        return (
            <div className="login-container-welcome">
                {/* Rain Background Theme */}
                <div className="rain-overlay">
                    <div className="atmospheric-light"></div>
                    <div className="surface-mist"></div>
                    {/* Raindrops */}
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    {/* Ripples */}
                    <div className="ripple"></div><div className="ripple"></div><div className="ripple"></div>
                    <div className="ripple"></div><div className="ripple"></div>
                </div>

                <div className="welcome-content">
                    <Shield className="welcome-shield" size={100} />
                    <h1 className="welcome-title">AutoDefenceX</h1>
                    <p className="welcome-org-name">{organizationName}</p>
                    <p className="welcome-tagline">Advanced Endpoint Protection & Threat Intelligence</p>

                    <button
                        className="access-btn"
                        onClick={() => setShowWelcome(false)}
                    >
                        <Lock size={20} />
                        Access
                    </button>
                </div>
            </div>
        );
    }

    if (!role) {
        return (
            <div className="login-container-split">
                {/* Rain Background Theme */}
                <div className="rain-overlay">
                    <div className="atmospheric-light"></div>
                    <div className="surface-mist"></div>
                    {/* Raindrops */}
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                    {/* Ripples */}
                    <div className="ripple"></div><div className="ripple"></div><div className="ripple"></div>
                    <div className="ripple"></div><div className="ripple"></div>
                </div>

                {/* Left Panel - Branding */}
                <div className="login-left-panel initial">
                    <div className="brand-content">
                        <Shield className="brand-shield" size={80} />
                        <h1 className="brand-title">AutoDefenceX</h1>
                        <p className="brand-subtitle">{organizationName}</p>
                        <div className="brand-tagline">Advanced Endpoint Protection & Threat Intelligence</div>
                    </div>
                </div>

                {/* Right Panel - Role Selection */}
                <div className="login-right-panel initial">
                    <div className="role-selection-content">
                        <h2 className="glow-text-split">Select Access Type</h2>
                        <p className="company-subtitle">Choose your login portal</p>

                        <div className="role-options">
                            <button className="role-card admin-card" onClick={() => setRole('admin')}>
                                <div className="role-icon-wrapper admin-bg">
                                    <Lock size={32} />
                                </div>
                                <h3>Admin Console</h3>
                                <p>Full system management and security control</p>
                                <div className="card-arrow">→</div>
                            </button>

                            <button className="role-card endpoint-card" onClick={() => setRole('user')}>
                                <div className="role-icon-wrapper endpoint-bg">
                                    <User size={32} />
                                </div>
                                <h3>Enterprise Endpoint</h3>
                                <p>Employee access and endpoint protection</p>
                                <div className="card-arrow">→</div>
                            </button>
                        </div>

                        <button className="text-btn mt-20" onClick={() => navigate('/register-admin')}>
                            New Organization? Register Admin Domain
                        </button>
                    </div>
                </div>
            </div>
        );
    }


    return (
        <div className="login-container-split">
            {/* Rain Background Theme */}
            <div className="rain-overlay">
                <div className="atmospheric-light"></div>
                <div className="surface-mist"></div>
                {/* Raindrops */}
                <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                <div className="raindrop"></div><div className="raindrop"></div><div className="raindrop"></div>
                {/* Ripples */}
                <div className="ripple"></div><div className="ripple"></div><div className="ripple"></div>
                <div className="ripple"></div><div className="ripple"></div>
            </div>

            {/* Left Panel - Dynamic Based on Role */}
            <div className={`login-left-panel ${role === 'admin' ? 'admin-theme' : 'endpoint-theme'}`}>
                <div className="brand-content animated">
                    {role === 'admin' ? (
                        <>
                            <div className="icon-circle admin-glow">
                                <Lock size={60} />
                            </div>
                            <h1 className="panel-title">Admin Console</h1>
                            <p className="panel-desc">Complete system control and security management</p>
                            <div className="feature-list">
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Endpoint Management</span>
                                </div>
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Security Analytics</span>
                                </div>
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Policy Configuration</span>
                                </div>
                            </div>
                        </>
                    ) : (
                        <>
                            <div className="icon-circle endpoint-glow">
                                <User size={60} />
                            </div>
                            <h1 className="panel-title">Endpoint Access</h1>
                            <p className="panel-desc">Secure employee portal with real-time protection</p>
                            <div className="feature-list">
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Real-time Protection</span>
                                </div>
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Threat Intelligence</span>
                                </div>
                                <div className="feature-item">
                                    <Shield size={18} />
                                    <span>Activity Tracking</span>
                                </div>
                            </div>

                            {/* Motivational Card for Endpoint Users */}
                            <div className="motivational-card">
                                <div className="quote-content">
                                    <span className="quote-mark">"</span>
                                    <p className="quote-text">{dailyQuote.text}</p>
                                    <p className="quote-author">— {dailyQuote.author}</p>
                                </div>
                                <div className="daily-badge">Daily Motivation</div>
                            </div>
                        </>
                    )}
                </div>
            </div>

            {/* Right Panel - Login Form */}
            <div className="login-right-panel login-form-panel">
                <div className={`login-box-split ${loginSuccess ? 'login-success' : ''}`}>
                    <h2 className="login-header-split">
                        <LogIn size={28} className="header-icon" />
                        {role === 'admin' ? 'Admin Access' : 'User Endpoint Login'}
                    </h2>

                    <form onSubmit={handleLogin} className="login-form">
                        {/* Company/User Name Display */}
                        {(companyName || userName) && (
                            <div className="company-indicator" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '4px' }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', width: '100%' }}>
                                    <i className={userName ? "fas fa-user" : "fas fa-building"}></i>
                                    <span>
                                        {userName && departmentName ? `${userName} (${departmentName})` : (userName || companyName)}
                                    </span>
                                    {usernameValid && <i className="fas fa-check-circle" style={{ color: '#34d399', marginLeft: 'auto' }}></i>}
                                </div>
                                {riskScore !== null && (
                                    <div className="risk-score-badge" style={{
                                        fontSize: '0.75rem',
                                        background: 'rgba(239, 68, 68, 0.15)',
                                        color: '#f87171',
                                        padding: '2px 8px',
                                        borderRadius: '4px',
                                        border: '1px solid rgba(239, 68, 68, 0.3)',
                                        marginTop: '4px'
                                    }}>
                                        <i className="fas fa-exclamation-triangle" style={{ marginRight: '5px' }}></i>
                                        Risk Score: {riskScore.toFixed(1)}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Username Input with Floating Label */}
                        <div className="floating-input-wrapper">
                            <input
                                type="text"
                                id="username-input"
                                value={username}
                                onChange={(e) => handleUsernameChange(e.target.value)}
                                required
                                className={`cyber-input floating-input ${usernameValid === false ? 'invalid' : ''} ${usernameValid === true ? 'valid' : ''}`}
                            />
                            <label htmlFor="username-input" className="floating-label">
                                Username
                            </label>
                            {checkingUsername && <div className="checking-indicator">...</div>}
                        </div>

                        {/* Password Input with Floating Label */}
                        <div className="floating-input-wrapper">
                            <input
                                type={showPassword ? "text" : "password"}
                                id="password-input"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                className="cyber-input floating-input"
                                disabled={otpRequired}
                            />
                            <label htmlFor="password-input" className="floating-label">
                                Password
                            </label>
                            <button
                                type="button"
                                className="password-toggle"
                                onClick={() => setShowPassword(!showPassword)}
                                aria-label="Toggle password visibility"
                                disabled={otpRequired}
                            >
                                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                            </button>
                        </div>

                        {otpRequired && (
                            <div className="otp-step slide-up" style={{ marginTop: '15px', padding: '15px', border: '1px solid #3b82f6', borderRadius: '8px', background: 'rgba(59, 130, 246, 0.05)' }}>
                                <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '10px' }}>
                                    <i className="fas fa-shield-alt" style={{ marginRight: '8px' }}></i>
                                    Security OTP sent to <strong>{maskedPhone}</strong>
                                </p>
                                <input
                                    type="text"
                                    placeholder="Enter Login OTP"
                                    value={loginOTP}
                                    onChange={(e) => setLoginOTP(e.target.value)}
                                    required
                                    className="cyber-input"
                                    autoFocus
                                />
                            </div>
                        )}

                        <div className="forgot-password-container">
                            {/* Forgot password link can be added here if needed */}
                        </div>

                        <button type="submit" className="login-btn secure-access-btn" disabled={isLoading}>
                            {isLoading ? (
                                <>
                                    <div className="spinner"></div>
                                    <span>Authenticating...</span>
                                </>
                            ) : (
                                <>
                                    <Lock size={18} /> {otpRequired ? 'Verify & Access' : 'Secure Access'}
                                </>
                            )}
                        </button>
                    </form>

                    {error && (
                        <div className="error-pill">
                            <XCircle size={16} /> {error}
                        </div>
                    )}

                    {regMsg && <p className="error-msg text-green">{regMsg}</p>}

                    <button className="back-link-styled" onClick={() => {
                        setRole(null);
                        setOtpRequired(false);
                        setLoginOTP('');
                    }}>
                        &larr; Back to Role Selection
                    </button>
                </div>
            </div>

            {/* Password Change Modal */}
            <PasswordChangeModal
                isOpen={showPasswordChange}
                onClose={() => setShowPasswordChange(false)}
                isForced={true}
                userInfo={passwordChangeUserInfo}
            />
        </div>
    );
};

export default Login;
