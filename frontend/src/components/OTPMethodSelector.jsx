import React, { useState } from 'react';
import { X, Mail, MessageSquare, Phone, Shield, Check, Send, AlertCircle } from 'lucide-react';
import axios from '../api';
import './OTPMethodSelector.css';

const METHOD_CONFIG = {
    email: {
        icon: Mail,
        label: 'Email',
        description: 'Receive OTP via email',
        iconClass: 'email-icon',
    },
    sms: {
        icon: MessageSquare,
        label: 'SMS',
        description: 'Receive OTP via text message',
        iconClass: 'sms-icon',
    },
    call: {
        icon: Phone,
        label: 'Voice Call',
        description: 'Receive OTP via phone call',
        iconClass: 'call-icon',
    },
};

const OTPMethodSelector = ({
    isOpen,
    onClose,
    username,
    availableMethods = [],
    maskedPhone,
    maskedEmail,
    onMethodSelected,
}) => {
    const [selectedMethod, setSelectedMethod] = useState(null);
    const [isSending, setIsSending] = useState(false);
    const [error, setError] = useState('');

    if (!isOpen) return null;

    const getDescription = (method) => {
        const base = METHOD_CONFIG[method]?.description || '';
        if (method === 'email' && maskedEmail) return `Send to ${maskedEmail}`;
        if ((method === 'sms' || method === 'call') && maskedPhone) return `Send to ${maskedPhone}`;
        return base;
    };

    const handleSendOTP = async () => {
        if (!selectedMethod) {
            setError('Please select a delivery method');
            return;
        }

        setIsSending(true);
        setError('');

        try {
            const response = await axios.post('/otp/login-send', {
                username: username,
                delivery_method: selectedMethod,
            });

            if (response.data.success) {
                // If debug OTP is returned (dev mode), log it for convenience
                if (response.data.debug_otp) {
                    console.log('🔐 DEBUG OTP:', response.data.debug_otp);
                }
                onMethodSelected(selectedMethod, response.data.message);
            } else {
                setError(response.data.message || 'Failed to send OTP');
            }
        } catch (err) {
            console.error('OTP Send Error:', err);
            setError(err.response?.data?.detail || 'Failed to send OTP. Please try again.');
        } finally {
            setIsSending(false);
        }
    };

    return (
        <div className="otp-method-overlay" onClick={(e) => e.target === e.currentTarget && onClose()}>
            <div className="otp-method-modal">
                {/* Header */}
                <div className="otp-method-header">
                    <button className="close-btn" onClick={onClose} aria-label="Close">
                        <X size={18} />
                    </button>
                    <div className="otp-method-shield-icon">
                        <Shield size={28} />
                    </div>
                    <h3>Two-Factor Authentication</h3>
                    <p>Choose how you'd like to receive your verification code</p>
                </div>

                {/* Content */}
                <div className="otp-method-content">
                    {/* Method Cards */}
                    <div className="otp-method-cards">
                        {availableMethods.map((method) => {
                            const config = METHOD_CONFIG[method];
                            if (!config) return null;
                            const IconComponent = config.icon;
                            const isSelected = selectedMethod === method;

                            return (
                                <div
                                    key={method}
                                    className={`otp-method-card ${isSelected ? 'selected' : ''}`}
                                    onClick={() => {
                                        setSelectedMethod(method);
                                        setError('');
                                    }}
                                    role="button"
                                    tabIndex={0}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' || e.key === ' ') {
                                            setSelectedMethod(method);
                                            setError('');
                                        }
                                    }}
                                >
                                    <div className={`otp-method-card-icon ${config.iconClass}`}>
                                        <IconComponent size={24} />
                                    </div>
                                    <div className="otp-method-card-info">
                                        <h4>{config.label}</h4>
                                        <p>{getDescription(method)}</p>
                                    </div>
                                    <div className="otp-method-card-check">
                                        <Check size={14} color="#fff" />
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="otp-method-error">
                            <AlertCircle size={16} style={{ flexShrink: 0 }} />
                            <span>{error}</span>
                        </div>
                    )}

                    {/* Send Button */}
                    <button
                        className="otp-method-send-btn"
                        onClick={handleSendOTP}
                        disabled={!selectedMethod || isSending}
                    >
                        {isSending ? (
                            <>
                                <div className="spinner"></div>
                                <span>Sending OTP...</span>
                            </>
                        ) : (
                            <>
                                <Send size={18} />
                                Send Verification Code
                            </>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default OTPMethodSelector;
