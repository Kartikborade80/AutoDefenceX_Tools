import React, { useState, useEffect } from 'react';
import { X, Check, Timer, RefreshCw, AlertCircle } from 'lucide-react';
import api from '../api';
import './OTPVerificationModal.css';

const OTPVerificationModal = ({ mobileNumber, isOpen, onClose, onVerified }) => {
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const [timer, setTimer] = useState(60);
    const [isSending, setIsSending] = useState(false);
    const [isVerifying, setIsVerifying] = useState(false);
    const [error, setError] = useState('');
    const [note, setNote] = useState('');
    const [otpSent, setOtpSent] = useState(false);

    // Initial setup when modal opens
    useEffect(() => {
        if (isOpen && mobileNumber && !otpSent && !isSending) {
            setOtp(['', '', '', '', '', '']);
            setError('');
            setNote('');
            setTimer(60);

            // Automatically send OTP when modal opens
            const timer = setTimeout(() => {
                sendOtp();
            }, 500);
            return () => clearTimeout(timer);
        }
    }, [isOpen, mobileNumber, otpSent, isSending]);

    // Timer countdown
    useEffect(() => {
        let interval;
        if (isOpen && timer > 0 && otpSent) {
            interval = setInterval(() => {
                setTimer((prev) => prev - 1);
            }, 1000);
        }
        return () => clearInterval(interval);
    }, [isOpen, timer, otpSent]);

    const sendOtp = async () => {
        if (!mobileNumber) {
            setError("Invalid mobile number");
            return;
        }

        try {
            setIsSending(true);
            setError('');

            const response = await api.post('/otp/send', {
                phone_number: mobileNumber
            });

            if (response.data.success) {
                setOtpSent(true);
                setTimer(300); // 5 minutes
                if (response.data.note) {
                    setNote(response.data.note);
                }

                // For development: show debug OTP in console
                if (response.data.debug_otp) {
                    console.log("🔐 DEBUG OTP:", response.data.debug_otp);
                }
            } else {
                setError(response.data.message || 'Failed to send OTP');
            }

        } catch (err) {
            console.error("Send OTP Error:", err);
            setError(err.response?.data?.detail || 'Failed to send OTP');
        } finally {
            setIsSending(false);
        }
    };

    const handleVerify = async () => {
        const otpCode = otp.join('');
        if (otpCode.length !== 6) {
            setError('Please enter complete 6-digit OTP');
            return;
        }

        try {
            setIsVerifying(true);
            setError('');

            const response = await api.post('/otp/verify', {
                phone_number: mobileNumber,
                otp_code: otpCode
            });

            if (response.data.success && response.data.verified) {
                // Success!
                onVerified();
                onClose();
            } else {
                setError(response.data.message || 'Invalid OTP code');
                if (response.data.attempts_remaining !== undefined) {
                    setError(`Invalid OTP. ${response.data.attempts_remaining} attempts remaining.`);
                }
            }

        } catch (err) {
            console.error("Verify Error:", err);
            setError(err.response?.data?.detail || 'Failed to verify OTP');
        } finally {
            setIsVerifying(false);
        }
    };

    const handleResend = async () => {
        setOtp(['', '', '', '', '', '']);
        setError('');
        await sendOtp();
    };

    const handleChange = (element, index) => {
        if (isNaN(element.value)) return;

        const newOtp = [...otp];
        newOtp[index] = element.value;
        setOtp(newOtp);

        if (element.value && element.nextSibling) {
            element.nextSibling.focus();
        }
    };

    const handleKeyDown = (e, index) => {
        if (e.key === 'Backspace' && !otp[index] && e.target.previousSibling) {
            e.target.previousSibling.focus();
        }
        if (e.key === 'Enter') {
            handleVerify();
        }
    };

    if (!isOpen) return null;

    return (
        <div className="otp-modal-overlay">
            <div className="otp-modal">
                <div className="otp-header">
                    <h3>Verify Mobile Number</h3>
                    <button className="close-btn" onClick={onClose}>
                        <X size={20} />
                    </button>
                </div>

                <div className="otp-content">
                    <p className="otp-subtitle">
                        Enter the 6-digit code sent to<br />
                        <strong>{mobileNumber.startsWith('+') ? mobileNumber : `+91 ${mobileNumber}`}</strong>
                    </p>

                    <div className="otp-inputs">
                        {otp.map((data, index) => (
                            <input
                                key={index}
                                type="text"
                                maxLength="1"
                                value={data}
                                onChange={(e) => handleChange(e.target, index)}
                                onKeyDown={(e) => handleKeyDown(e, index)}
                                onFocus={(e) => e.target.select()}
                                disabled={!otpSent || isSending}
                            />
                        ))}
                    </div>

                    {error && (
                        <div className="otp-error">
                            <AlertCircle size={16} style={{ flexShrink: 0 }} />
                            <span>{error}</span>
                        </div>
                    )}

                    {isSending && (
                        <div className="otp-status">Sending verification code...</div>
                    )}

                    {otpSent && !error && !isSending && (
                        <div className="otp-success-note">
                            {note || (mobileNumber ? "OTP sent successfully." : "")}
                        </div>
                    )}

                    <div className="otp-actions">
                        <button
                            className="verify-btn"
                            onClick={handleVerify}
                            disabled={isVerifying || !otpSent}
                        >
                            {isVerifying ? 'Verifying...' : 'Verify OTP'}
                        </button>
                    </div>

                    <div className="otp-footer">
                        {timer > 0 ? (
                            <span className="timer">
                                <Timer size={16} /> Resend in {timer}s
                            </span>
                        ) : (
                            <button
                                className="resend-btn"
                                onClick={handleResend}
                                disabled={isSending}
                            >
                                <RefreshCw size={16} /> Resend OTP
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default OTPVerificationModal;
