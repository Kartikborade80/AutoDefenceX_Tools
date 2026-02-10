import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, Zap, Radio, Globe } from 'lucide-react';
import './Dashboard.css'; // Make sure to add styles here or inline

const LiveScanner = ({ title = "Live Network Monitor", type = "admin" }) => {
    const [scannedItems, setScannedItems] = useState([]);
    const [activeThreats, setActiveThreats] = useState(0);
    const scrollRef = useRef(null);

    // Random Data Generators
    const generateIP = () => `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const threats = ["SQL Injection", "XSS Attempt", "Brute Force", "Malware Sig", "Port Scan", "DDoS Packet"];
    const statuses = ["CLEAN", "SECURE", "ANALYZING", "FILTERED"];

    useEffect(() => {
        const interval = setInterval(() => {
            const isThreat = Math.random() > 0.9;
            const newItem = {
                id: Date.now(),
                timestamp: new Date().toLocaleTimeString(),
                source: generateIP(),
                action: isThreat ? threats[Math.floor(Math.random() * threats.length)] : "Traffic Analysis",
                status: isThreat ? "BLOCKED" : statuses[Math.floor(Math.random() * statuses.length)],
                severity: isThreat ? "HIGH" : "LOW"
            };

            setScannedItems(prev => {
                const updated = [...prev, newItem];
                if (updated.length > 20) updated.shift(); // Keep list short
                return updated;
            });

            if (isThreat) setActiveThreats(prev => prev + 1);

            // Auto-scroll
            if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
            }

        }, 800); // Speed of scan

        return () => clearInterval(interval);
    }, []);

    // Visuals based on type
    const isPersonal = type === 'personal';
    const accentColor = isPersonal ? 'var(--secondary)' : 'var(--primary)'; // personal uses purple/secondary

    return (
        <div className={`live-scanner-panel ${isPersonal ? 'personal-mode' : ''}`}>
            <div className="scanner-header">
                <h3>
                    {isPersonal ? <Zap size={20} className="pulse-icon" /> : <Activity size={20} className="spin-slow" />}
                    {title}
                </h3>
                <div className="scanner-meta">
                    <span className="live-indicator"><div className="blink-dot"></div> LIVE</span>
                    <span className="scanned-count"> threats blocked: {activeThreats}</span>
                </div>
            </div>

            <div className="scanner-visual">
                {/* Simulated Swarm Visual */}
                <div className="swarm-grid">
                    <div className="grid-line horizontal"></div>
                    <div className="grid-line vertical"></div>
                    <div className="radar-sweep"></div>
                </div>
            </div>

            <div className="scanner-log" ref={scrollRef}>
                {scannedItems.map((item, idx) => (
                    <div key={item.id} className={`log-line ${item.status === 'BLOCKED' ? 'threat' : 'clean'}`}>
                        <span className="log-time">[{item.timestamp}]</span>
                        <span className="log-source"> SRC:{item.source}</span>
                        <span className="log-action"> :: {item.action}</span>
                        <span className="log-status"> [{item.status}]</span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default LiveScanner;
