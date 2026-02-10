import React, { useState, useEffect } from 'react';
import axios from '../api';
import { ShieldCheck, TrendingUp, AlertOctagon } from 'lucide-react';
import './DashboardEnhanced.css';

const TrustScore = () => {
    const [score, setScore] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchScore = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get('/reports/my-score', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setScore(res.data.trust_score);
            } catch (err) {
                console.error("Failed to fetch trust score");
            } finally {
                setLoading(false);
            }
        };
        fetchScore();
    }, []);

    const getScoreColor = (s) => {
        if (s >= 80) return '#10b981'; // Green
        if (s >= 50) return '#f59e0b'; // Yellow
        return '#ef4444'; // Red
    };

    return (
        <div className="card trust-score-card">
            <h3><ShieldCheck size={22} /> My Trust Score</h3>
            <div className="score-display">
                <svg viewBox="0 0 36 36" className="circular-chart">
                    <path className="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                    <path
                        className="circle"
                        strokeDasharray={`${score}, 100`}
                        d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                        style={{ stroke: getScoreColor(score) }}
                    />
                    <text x="18" y="20.35" className="percentage" style={{ fill: getScoreColor(score) }}>{score}</text>
                </svg>
            </div>
            <div className="score-feedback">
                {score >= 80 ? (
                    <p className="text-green"><TrendingUp size={14} /> Excellent standing</p>
                ) : (
                    <p className="text-red"><AlertOctagon size={14} /> Action Required</p>
                )}
            </div>
        </div>
    );
};

export default TrustScore;
