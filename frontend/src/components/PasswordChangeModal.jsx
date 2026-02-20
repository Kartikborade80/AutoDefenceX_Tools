import React, { useState } from 'react';
import './PasswordChangeModal.css';
import api from '../api';

const PasswordChangeModal = ({ isOpen, onClose, isForced = false, userInfo }) => {
    const [oldPassword, setOldPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [showOldPassword, setShowOldPassword] = useState(false);
    const [showNewPassword, setShowNewPassword] = useState(false);

    // Clear error when modal opens
    React.useEffect(() => {
        if (isOpen) {
            setError('');
            setOldPassword('');
            setNewPassword('');
            setConfirmPassword('');
        }
    }, [isOpen]);

    // Password strength calculation
    const calculatePasswordStrength = (password) => {
        let strength = 0;
        if (password.length >= 12) strength += 25;
        if (/[a-z]/.test(password)) strength += 15;
        if (/[A-Z]/.test(password)) strength += 15;
        if (/[0-9]/.test(password)) strength += 15;
        if (/[^a-zA-Z0-9]/.test(password)) strength += 15;
        if (password.length >= 16) strength += 15;
        return Math.min(strength, 100);
    };

    const getStrengthLabel = (strength) => {
        if (strength < 40) return { label: 'Weak', color: '#ef4444' };
        if (strength < 70) return { label: 'Medium', color: '#f59e0b' };
        return { label: 'Strong', color: '#10b981' };
    };

    const strength = calculatePasswordStrength(newPassword);
    const strengthInfo = getStrengthLabel(strength);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        if (newPassword !== confirmPassword) {
            setError('New passwords do not match');
            return;
        }

        if (newPassword.length < 12) {
            setError('Password must be at least 12 characters long');
            return;
        }

        setLoading(true);

        try {
            let response;

            if (isForced && userInfo) {
                // Use forced change endpoint (no auth required)
                response = await api.post('/password/change-forced', {
                    username: userInfo.username,
                    old_password: oldPassword,
                    new_password: newPassword
                });
            } else {
                // Use regular change endpoint (requires auth)
                response = await api.post('/password/change', {
                    old_password: oldPassword,
                    new_password: newPassword
                });
            }

            if (response.data.success) {
                alert('Password changed successfully! Please login again.');
                // Clear local storage and redirect to login
                localStorage.removeItem('token');
                window.location.href = '/';
            }
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to change password');
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="password-modal-overlay">
            <div className="password-modal">
                <div className="password-modal-header">
                    <h2>🔒 Change Password</h2>
                    {!isForced && (
                        <button className="close-btn" onClick={onClose}>×</button>
                    )}
                </div>

                <form onSubmit={handleSubmit} className="password-form">
                    {error && <div className="error-message">{error}</div>}

                    <div className="form-group">
                        <label>Current Password</label>
                        <div className="password-input-wrapper">
                            <input
                                type={showOldPassword ? "text" : "password"}
                                value={oldPassword}
                                onChange={(e) => setOldPassword(e.target.value)}
                                required
                                placeholder="Enter your current password"
                            />
                            <button
                                type="button"
                                className="toggle-password"
                                onClick={() => setShowOldPassword(!showOldPassword)}
                            >
                                {showOldPassword ? '👁️' : '👁️‍🗨️'}
                            </button>
                        </div>
                    </div>

                    <div className="form-group">
                        <label>New Password</label>
                        <div className="password-input-wrapper">
                            <input
                                type={showNewPassword ? "text" : "password"}
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                required
                                placeholder="Enter new password (min 12 characters)"
                            />
                            <button
                                type="button"
                                className="toggle-password"
                                onClick={() => setShowNewPassword(!showNewPassword)}
                            >
                                {showNewPassword ? '👁️' : '👁️‍🗨️'}
                            </button>
                        </div>
                        {newPassword && (
                            <div className="strength-meter">
                                <div className="strength-bar-bg">
                                    <div
                                        className="strength-bar"
                                        style={{
                                            width: `${strength}%`,
                                            backgroundColor: strengthInfo.color
                                        }}
                                    />
                                </div>
                                <span style={{ color: strengthInfo.color }}>
                                    {strengthInfo.label}
                                </span>
                            </div>
                        )}
                        <div className="password-requirements">
                            <p>Password must contain:</p>
                            <ul>
                                <li className={newPassword.length >= 12 ? 'met' : ''}>
                                    ✓ At least 12 characters
                                </li>
                                <li className={/[A-Z]/.test(newPassword) ? 'met' : ''}>
                                    ✓ One uppercase letter
                                </li>
                                <li className={/[a-z]/.test(newPassword) ? 'met' : ''}>
                                    ✓ One lowercase letter
                                </li>
                                <li className={/[0-9]/.test(newPassword) ? 'met' : ''}>
                                    ✓ One number
                                </li>
                                <li className={/[^a-zA-Z0-9]/.test(newPassword) ? 'met' : ''}>
                                    ✓ One special character
                                </li>
                            </ul>
                        </div>
                    </div>

                    <div className="form-group">
                        <label>Confirm New Password</label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            placeholder="Re-enter new password"
                        />
                    </div>

                    <div className="modal-actions">
                        <button
                            type="submit"
                            className="submit-btn"
                            disabled={loading || strength < 40}
                        >
                            {loading ? 'Changing...' : 'Change Password'}
                        </button>
                        {!isForced && (
                            <button type="button" className="cancel-btn" onClick={onClose}>
                                Cancel
                            </button>
                        )}
                    </div>
                </form>
            </div>
        </div>
    );
};

export default PasswordChangeModal;
