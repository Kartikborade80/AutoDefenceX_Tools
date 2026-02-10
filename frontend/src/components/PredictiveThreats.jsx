import React, { useState, useEffect } from 'react';
import { TrendingUp, AlertTriangle, ShieldCheck, Activity } from 'lucide-react';
import axios from '../api';
import './Dashboard.css';

const PredictiveThreats = () => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get('/analytics/benchmarks', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setData(res.data);
            } catch (err) {
                console.error("Failed to fetch predictive analytics", err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, []);

    if (loading) {
        return (
            <div className="dashboard-container fade-in">
                <header className="dashboard-header">
                    <h2><TrendingUp className="icon-lg" /> Predictive Threat Analytics</h2>
                </header>
                <div className="loading-container">
                    <Activity className="spin text-blue" size={48} />
                    <p style={{ marginTop: '15px', color: '#94a3b8' }}>Analyzing Global Threat Vectors...</p>
                </div>
            </div>
        );
    }

    if (!data) return null;

    // Extracting insights for display
    const topInsight = data.insights.find(i => i.score < i.benchmark) || data.insights[0];

    return (
        <div className="dashboard-container fade-in">
            <header className="dashboard-header">
                <h2><TrendingUp className="icon-lg" /> Predictive Threat Analytics</h2>
            </header>

            <div className="metrics-grid-enhanced">
                <div className="metric-card primary">
                    <div className="metric-header"><Activity size={16} /> GLOBAL RANK</div>
                    <div className="metric-value">{data.global_rank}</div>
                    <div className="metric-subtitle">vs Industry Peers</div>
                </div>
                <div className="metric-card success">
                    <div className="metric-header"><ShieldCheck size={16} /> INDUSTRY PERCENTILE</div>
                    <div className="metric-value">{data.industry_percentile}%</div>
                    <div className="metric-subtitle">Security Maturity Score</div>
                </div>
            </div>

            <div className="card full-width">
                <h3><AlertTriangle className="text-red" size={20} style={{ marginRight: '10px', verticalAlign: 'bottom' }} /> Critical Risk Forecast</h3>
                <p style={{ fontSize: '1.2em', marginBottom: '15px' }}>
                    AI Analysis indicates <strong className="text-red">Elevated Risk</strong> in {topInsight.category}.
                    Your score of <strong>{topInsight.score}</strong> is below the industry benchmark of <strong>{topInsight.benchmark}</strong>.
                </p>

                <h4>Top 3 AI-Generated Insights:</h4>
                <ul className="timeline-list">
                    {data.insights.map((insight, index) => (
                        <li key={index} style={{ marginBottom: '10px' }}>
                            <strong>{insight.category}:</strong> {insight.insight}
                        </li>
                    ))}
                </ul>

                <div className="alert-item warning" style={{ marginTop: '20px' }}>
                    <AlertTriangle size={20} color="#f59e0b" style={{ marginRight: '10px' }} />
                    <span><strong>Recommendation:</strong> {topInsight.recommendation}</span>
                </div>
            </div>
        </div>
    );
};

export default PredictiveThreats;
