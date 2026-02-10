import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { HelpCircle, Mail, Book, AlertCircle, Settings, Shield, ChevronDown, ChevronUp } from 'lucide-react';
import './Dashboard.css';

const Help = () => {
    const [expandedFaq, setExpandedFaq] = useState(null);

    const faqs = [
        {
            question: "What is AutoDefenceX?",
            answer: "AutoDefenceX is a comprehensive endpoint security and management platform designed to protect your organization's devices, monitor threats in real-time, and enforce security policies across all endpoints. It provides advanced features like predictive threat detection, network healing, forensics, and compliance monitoring."
        },
        {
            question: "How do I add a new user or employee?",
            answer: "Navigate to User Management from the sidebar, click 'Generate New User', fill in the employee details (Full Name, Job Title, etc.), and use the Auto-Generate feature to automatically create Employee ID, Email, and Asset ID. You can also set access controls like USB blocking and wallpaper locking."
        },
        {
            question: "How do I apply security policies to endpoints?",
            answer: "Go to the Policies section from the sidebar. You can create and manage various policies including USB port blocking, wallpaper locking, firewall rules, application whitelisting, and more. Assign policies to specific users or groups, and they will be automatically enforced on their endpoints."
        },
        {
            question: "What should I do if an endpoint shows as offline?",
            answer: "Check the Endpoints page to view the status of all devices. If an endpoint is offline, ensure the device is powered on and connected to the network. Verify that the AutoDefenceX agent is running on the endpoint. You can also try restarting the agent service from the Endpoints management page."
        },
        {
            question: "How do I generate reports?",
            answer: "Visit the Reports section where you can generate various types of reports including per-employee reports, all-employees reports, security incident reports, compliance reports, and custom reports. Select the report type, choose the date range, and click 'Generate Report'."
        },
        {
            question: "What is Predictive Threat Detection?",
            answer: "Predictive Threat Detection uses AI and machine learning to analyze patterns and behaviors across your network to identify potential security threats before they occur. It provides threat forecasts, risk scores, and recommended actions to prevent security incidents."
        },
        {
            question: "How does Network Healing work?",
            answer: "Network Healing automatically detects and remediates network issues and security vulnerabilities. It can quarantine compromised assets, rollback malicious changes, and restore systems to known good states. You can view quarantined assets and manage rollback points from the Network Healing page."
        },
        {
            question: "How do I submit a support ticket?",
            answer: "Navigate to the Tickets section from the sidebar. Click 'Submit New Ticket', fill in the ticket details including subject, priority, and description, and submit. Administrators can view and respond to all tickets from the same page."
        },
        {
            question: "What are the different user roles?",
            answer: "AutoDefenceX has three main user roles: 1) Admin - Full access to all features including user management, policies, and system settings. 2) Endpoint Agent - Access to endpoint-specific features and monitoring. 3) Personal Security User - Standard users with access to their own profile and basic security features."
        },
        {
            question: "How do I change my password?",
            answer: "Currently, password changes must be requested through your administrator. Contact your IT admin or submit a support ticket to request a password reset. We recommend using strong, unique passwords for your account."
        },
        {
            question: "What information is shown in System Information?",
            answer: "The System Information page displays comprehensive details about your endpoint including hardware specifications (CPU, RAM, Storage), operating system details, network configuration, installed security software, and current security posture."
        },
        {
            question: "How do I use the Forensics feature?",
            answer: "The Forensics section allows you to perform deep security analysis and investigations. You can run deep scans, analyze suspicious files, review security logs, track user activities, and investigate security incidents. Use the search and filter options to find specific events or patterns."
        }
    ];

    const toggleFaq = (index) => {
        setExpandedFaq(expandedFaq === index ? null : index);
    };

    const navigate = useNavigate();

    const scrollToSection = (id) => {
        const element = document.getElementById(id);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth' });
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><HelpCircle className="icon-lg" /> Help & Support Center</h2>
                <div className="header-meta">
                    <span className="badge blue">24/7 SUPPORT</span>
                </div>
            </header>

            {/* Contact Support Card */}
            <div className="card full-width" style={{ background: 'linear-gradient(135deg, var(--primary) 0%, var(--accent-glow) 100%)', color: 'white', marginBottom: '2rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '2rem', padding: '1rem' }}>
                    <Mail size={48} />
                    <div style={{ flex: 1 }}>
                        <h3 style={{ margin: '0 0 0.5rem 0', color: 'white' }}>Need Help? Contact Us</h3>
                        <p style={{ margin: '0 0 1rem 0', opacity: 0.9 }}>
                            Our support team is here to help you 24/7. Send us an email and we'll get back to you as soon as possible.
                        </p>
                        <a
                            href="mailto:autodefense.x@gmail.com"
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '8px',
                                padding: '10px 20px',
                                background: 'white',
                                color: 'var(--primary)',
                                borderRadius: '6px',
                                textDecoration: 'none',
                                fontWeight: '600',
                                transition: 'transform 0.2s'
                            }}
                            onMouseOver={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                            onMouseOut={(e) => e.currentTarget.style.transform = 'scale(1)'}
                        >
                            <Mail size={18} />
                            autodefense.x@gmail.com
                        </a>
                    </div>
                </div>
            </div>

            {/* Quick Links */}
            <section className="section-title">
                <h3>Quick Access</h3>
            </section>
            <div className="stats-grid">
                <div className="metric-box blue-border" style={{ cursor: 'pointer' }} onClick={() => scrollToSection('features')}>
                    <Book size={32} style={{ color: 'var(--primary)', marginBottom: '1rem' }} />
                    <h4>Documentation</h4>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Complete user guides</p>
                </div>
                <div className="metric-box green-border" style={{ cursor: 'pointer' }} onClick={() => scrollToSection('troubleshooting')}>
                    <AlertCircle size={32} style={{ color: 'var(--success)', marginBottom: '1rem' }} />
                    <h4>Troubleshooting</h4>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Common issues & fixes</p>
                </div>
                <div className="metric-box yellow-border" style={{ cursor: 'pointer' }} onClick={() => navigate('/pc-info')}>
                    <Settings size={32} style={{ color: 'var(--warning)', marginBottom: '1rem' }} />
                    <h4>System Status</h4>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Check service health</p>
                </div>
                <div className="metric-box blue-border" style={{ cursor: 'pointer' }} onClick={() => navigate('/policies')}>
                    <Shield size={32} style={{ color: 'var(--primary)', marginBottom: '1rem' }} />
                    <h4>Security Best Practices</h4>
                    <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Stay protected</p>
                </div>
            </div>

            {/* Frequently Asked Questions */}
            <div className="card full-width">
                <h3><HelpCircle size={20} /> Frequently Asked Questions</h3>
                <div style={{ marginTop: '1.5rem' }}>
                    {faqs.map((faq, index) => (
                        <div
                            key={index}
                            style={{
                                marginBottom: '1rem',
                                border: '1px solid var(--border-color)',
                                borderRadius: '8px',
                                overflow: 'hidden',
                                background: 'var(--bg-acrylic)'
                            }}
                        >
                            <div
                                onClick={() => toggleFaq(index)}
                                style={{
                                    padding: '1rem 1.5rem',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    transition: 'background 0.2s'
                                }}
                                onMouseOver={(e) => e.currentTarget.style.background = 'var(--bg-main)'}
                                onMouseOut={(e) => e.currentTarget.style.background = 'transparent'}
                            >
                                <h4 style={{ margin: 0, color: 'var(--text-primary)', fontSize: '1rem' }}>
                                    {faq.question}
                                </h4>
                                {expandedFaq === index ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                            </div>
                            {expandedFaq === index && (
                                <div style={{
                                    padding: '0 1.5rem 1.5rem 1.5rem',
                                    color: 'var(--text-secondary)',
                                    lineHeight: '1.6',
                                    borderTop: '1px solid var(--border-color)'
                                }}>
                                    {faq.answer}
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            </div>

            {/* Software Features Overview */}
            <div className="card full-width" id="features">
                <h3><Book size={20} /> Software Features</h3>
                <div className="grid-container" style={{ marginTop: '1.5rem' }}>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>🛡️ Endpoint Protection</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Real-time monitoring and protection for all endpoints. Track device status, enforce security policies, and respond to threats instantly.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>👥 User Management</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Comprehensive employee directory with auto-generation of credentials, access control management, and role-based permissions.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>📋 Policy Enforcement</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Create and deploy security policies including USB blocking, wallpaper locking, firewall rules, and application controls.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>📊 Advanced Reporting</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Generate detailed reports on security incidents, compliance status, user activities, and system health.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>🔍 Forensics & Investigation</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Deep security analysis, threat investigation, log analysis, and incident response capabilities.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>🤖 AI-Powered Threat Detection</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Predictive threat analysis using machine learning to identify and prevent security incidents before they occur.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>🔧 Network Healing</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Automated remediation of network issues, quarantine management, and system rollback capabilities.
                        </p>
                    </div>
                    <div style={{ padding: '1rem', background: 'var(--bg-acrylic)', borderRadius: '8px' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>✅ Compliance Monitoring</h4>
                        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.6' }}>
                            Track compliance with industry standards, generate audit reports, and maintain security certifications.
                        </p>
                    </div>
                </div>
            </div>

            {/* Troubleshooting Guide */}
            <div className="card full-width" id="troubleshooting">
                <h3><AlertCircle size={20} /> Common Troubleshooting</h3>
                <div style={{ marginTop: '1.5rem' }}>
                    <div style={{ marginBottom: '1.5rem' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>🔴 Agent Not Connecting</h4>
                        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
                            <li>Verify network connectivity and firewall settings</li>
                            <li>Ensure the AutoDefenceX agent service is running</li>
                            <li>Check that the correct server address is configured</li>
                            <li>Restart the agent service and check logs</li>
                        </ul>
                    </div>
                    <div style={{ marginBottom: '1.5rem' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>⚠️ Policy Not Applying</h4>
                        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
                            <li>Verify the policy is assigned to the correct user or group</li>
                            <li>Check that the endpoint is online and connected</li>
                            <li>Force a policy refresh from the Policies page</li>
                            <li>Review policy conflicts that might prevent application</li>
                        </ul>
                    </div>
                    <div style={{ marginBottom: '1.5rem' }}>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>📧 Login Issues</h4>
                        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
                            <li>Verify your username and password are correct</li>
                            <li>Check if your account is active and not locked</li>
                            <li>Clear browser cache and cookies</li>
                            <li>Contact your administrator for password reset</li>
                        </ul>
                    </div>
                    <div>
                        <h4 style={{ color: 'var(--primary)', marginBottom: '0.5rem' }}>💾 Report Generation Failing</h4>
                        <ul style={{ color: 'var(--text-secondary)', lineHeight: '1.8', paddingLeft: '1.5rem' }}>
                            <li>Ensure you have sufficient permissions to generate reports</li>
                            <li>Check that the date range is valid</li>
                            <li>Verify there is data available for the selected period</li>
                            <li>Try generating a smaller report first</li>
                        </ul>
                    </div>
                </div>
            </div>

            {/* Contact Footer */}
            <div className="card full-width" style={{ textAlign: 'center', background: 'var(--bg-acrylic)' }}>
                <h3>Still Need Help?</h3>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    Can't find the answer you're looking for? Our support team is ready to assist you.
                </p>
                <div className="btn-container-centered">
                    <a
                        href="mailto:autodefense.x@gmail.com"
                        className="btn-modern-primary"
                        style={{ textDecoration: 'none' }}
                    >
                        <Mail size={18} />
                        Email Support
                    </a>
                    <button className="btn-modern-success" onClick={() => window.location.href = '/tickets'}>
                        <HelpCircle size={18} />
                        Submit Ticket
                    </button>
                    <button className="btn-modern-secondary" onClick={() => window.history.back()}>
                        Cancel
                    </button>
                </div>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginTop: '1.5rem' }}>
                    Support Hours: 24/7 | Average Response Time: 2-4 hours
                </p>
            </div>
        </div>
    );
};

export default Help;
