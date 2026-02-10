import React, { useState, useEffect } from 'react';
import { Shield, Zap, AlertTriangle, CheckCircle, X, Cpu, HardDrive, Activity } from 'lucide-react';
import './ScanningPopup.css';

// Helper to get API URL
const getApiUrl = () => {
    if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        return 'http://localhost:8000';
    }
    return '';
};

const API_URL = getApiUrl();

const ScanningPopup = ({ isOpen, onClose, scanId, token }) => {
    const [scanData, setScanData] = useState(null);
    const [isScanning, setIsScanning] = useState(true);

    useEffect(() => {
        if (!isOpen || !scanId) return;

        const pollInterval = setInterval(async () => {
            try {
                const response = await fetch(`${API_URL}/scans/status/${scanId}`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
                const data = await response.json();
                setScanData(data);

                if (data.status === 'completed') {
                    setIsScanning(false);
                    clearInterval(pollInterval);

                    // Auto-close after 5 seconds on completion
                    setTimeout(() => {
                        onClose();
                    }, 5000);
                }
            } catch (error) {
                console.error('Error polling scan status:', error);
            }
        }, 500); // Poll every 500ms for smooth progress

        return () => clearInterval(pollInterval);
    }, [isOpen, scanId, token, onClose]);

    if (!isOpen) return null;

    const progress = scanData?.scan_progress || 0;
    const securityScore = scanData?.security_score || 0;
    const threatCount = scanData?.threat_count || 0;
    const defenderStatus = scanData?.defender_status || 'Initializing...';
    const systemHealth = scanData?.system_health || {};

    // Determine security level color
    const getScoreColor = (score) => {
        if (score >= 80) return '#10b981'; // green
        if (score >= 60) return '#f59e0b'; // yellow
        return '#ef4444'; // red
    };

    const scoreColor = getScoreColor(securityScore);

    return (
        <div className="scanning-popup-overlay" onClick={onClose}>
            <div className="scanning-popup-container" onClick={(e) => e.stopPropagation()}>
                <button className="scanning-popup-close" onClick={onClose}>
                    <X size={20} />
                </button>

                <div className="scanning-popup-header">
                    <div className="scanning-icon-wrapper">
                        <Shield size={40} className={isScanning ? 'pulse-icon' : ''} />
                    </div>
                    <h2>{isScanning ? 'Scanning System...' : 'Scan Complete'}</h2>
                    <p className="scanning-subtitle">{defenderStatus}</p>
                </div>

                {/* Circular Progress */}
                <div className="circular-progress-container">
                    <svg className="circular-progress" viewBox="0 0 200 200">
                        <circle
                            className="progress-bg"
                            cx="100"
                            cy="100"
                            r="85"
                        />
                        <circle
                            className="progress-bar"
                            cx="100"
                            cy="100"
                            r="85"
                            style={{
                                strokeDashoffset: 534 - (534 * progress) / 100,
                                stroke: isScanning ? '#3b82f6' : scoreColor
                            }}
                        />
                    </svg>
                    <div className="progress-text">
                        <div className="progress-percentage">
                            {isScanning ? `${progress}%` : `${securityScore}`}
                        </div>
                        <div className="progress-label">
                            {isScanning ? 'Progress' : 'Security Score'}
                        </div>
                    </div>
                </div>

                {/* Scan Details */}
                {!isScanning && (
                    <div className="scan-results">
                        <div className="result-card">
                            <div className="result-icon">
                                {threatCount === 0 ? (
                                    <CheckCircle size={24} className="text-success" />
                                ) : (
                                    <AlertTriangle size={24} className="text-warning" />
                                )}
                            </div>
                            <div className="result-info">
                                <div className="result-label">Threats Detected</div>
                                <div className="result-value">{threatCount}</div>
                            </div>
                        </div>

                        <div className="result-card">
                            <div className="result-icon">
                                <Cpu size={24} className="text-info" />
                            </div>
                            <div className="result-info">
                                <div className="result-label">CPU Usage</div>
                                <div className="result-value">{systemHealth.cpu_usage?.toFixed(1) || 0}%</div>
                            </div>
                        </div>

                        <div className="result-card">
                            <div className="result-icon">
                                <Activity size={24} className="text-primary" />
                            </div>
                            <div className="result-info">
                                <div className="result-label">RAM Usage</div>
                                <div className="result-value">{systemHealth.ram_usage?.toFixed(1) || 0}%</div>
                            </div>
                        </div>

                        <div className="result-card">
                            <div className="result-icon">
                                <HardDrive size={24} className="text-secondary" />
                            </div>
                            <div className="result-info">
                                <div className="result-label">Processes</div>
                                <div className="result-value">{systemHealth.process_count || 0}</div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Scanning Animation */}
                {isScanning && (
                    <div className="scanning-animation">
                        <div className="scan-line"></div>
                        <p className="scanning-text">Analyzing system security...</p>
                    </div>
                )}

                {/* Status Message */}
                {!isScanning && (
                    <div className={`status-message ${securityScore >= 80 ? 'success' : securityScore >= 60 ? 'warning' : 'danger'}`}>
                        {securityScore >= 80 && (
                            <>
                                <CheckCircle size={20} />
                                <span>Your system is secure!</span>
                            </>
                        )}
                        {securityScore >= 60 && securityScore < 80 && (
                            <>
                                <AlertTriangle size={20} />
                                <span>Minor security concerns detected</span>
                            </>
                        )}
                        {securityScore < 60 && (
                            <>
                                <AlertTriangle size={20} />
                                <span>Action required to improve security</span>
                            </>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};

export default ScanningPopup;
