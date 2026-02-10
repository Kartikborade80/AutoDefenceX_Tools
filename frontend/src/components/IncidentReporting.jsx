import React, { useState } from 'react';
import axios from '../api';
import { AlertTriangle, Send, Loader, CheckCircle } from 'lucide-react';
import './DashboardEnhanced.css';

const IncidentReporting = () => {
    const [type, setType] = useState('Phishing Attempt');
    const [description, setDescription] = useState('');
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const token = localStorage.getItem('token');
            await axios.post('/reports/incident',
                { type, description },
                { headers: { Authorization: `Bearer ${token}` } }
            );
            setSuccess(true);
            setDescription('');
            setTimeout(() => setSuccess(false), 3000);
        } catch (err) {
            alert('Failed to submit report. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="card incident-reporting-card">
            <div className="card-header danger-header">
                <h3><AlertTriangle size={20} className="text-white" /> Report Incident</h3>
            </div>

            <form onSubmit={handleSubmit} className="incident-form">
                <div className="form-group">
                    <label>Incident Type</label>
                    <select value={type} onChange={(e) => setType(e.target.value)} className="cyber-select">
                        <option>Phishing Attempt</option>
                        <option>Malware / Virus</option>
                        <option>Suspicious Activity</option>
                        <option>Lost Device</option>
                        <option>Hardware Failure</option>
                    </select>
                </div>

                <div className="form-group">
                    <label>Description</label>
                    <textarea
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        placeholder="Describe what happened..."
                        required
                        className="cyber-textarea"
                    />
                </div>

                <button type="submit" className={`cyber-button danger w-full ${loading ? 'loading' : ''}`} disabled={loading}>
                    {loading ? <Loader className="spin" size={16} /> : (success ? <CheckCircle size={16} /> : <Send size={16} />)}
                    {success ? 'Report Sent!' : 'Submit Report'}
                </button>
            </form>
        </div>
    );
};

export default IncidentReporting;
