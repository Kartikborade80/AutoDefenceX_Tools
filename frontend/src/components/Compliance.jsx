import React from 'react';
import { ClipboardCheck, FileText } from 'lucide-react';
import './Dashboard.css';

const Compliance = () => {
    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><ClipboardCheck className="icon-lg" /> Reports & Compliance Center</h2>
                <span className="badge green">99% COMPLIANT</span>
            </header>

            <div className="card full-width">
                <h3>Audit Status</h3>
                <div className="grid-container" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginTop: '20px' }}>
                    <div className="metric-box green-border">
                        <h4>GDPR</h4>
                        <p style={{ fontSize: '1.5rem' }}>99.5%</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>HIPAA</h4>
                        <p style={{ fontSize: '1.5rem' }}>98.7%</p>
                    </div>
                    <div className="metric-box green-border">
                        <h4>ISO 27001</h4>
                        <p style={{ fontSize: '1.5rem' }}>100%</p>
                    </div>
                </div>

                <p style={{ marginTop: '20px' }}>
                    Last Audit Report (Q3 2025) successfully generated. PCI DSS generation scheduled for next month.
                </p>
            </div>
        </div>
    );
};

export default Compliance;
