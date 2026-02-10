import React, { useState, useEffect } from 'react';
import axios from '../api';
import {
    Globe,
    Monitor,
    ShieldAlert,
    ShieldCheck,
    RefreshCw,
    Activity,
    Info
} from 'lucide-react';
import './NetworkTopology.css';
import './DashboardEnhanced.css';

const NetworkTopology = () => {
    const [data, setData] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);
    const [selectedNode, setSelectedNode] = useState(null);

    const fetchTopology = async () => {
        try {
            setLoading(true);
            const token = localStorage.getItem('token');
            const response = await axios.get('/analytics/topology', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setData(response.data);
        } catch (err) {
            console.error("Error fetching topology:", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTopology();
    }, []);

    // Helper to calculate node positions in a radial layout
    const getCoordinates = (index, total, radius = 250, centerX = 400, centerY = 350) => {
        if (index === 0) return { x: centerX, y: centerY }; // Gateway at center
        if (total <= 1) return { x: centerX, y: centerY }; // Safety check for single/no nodes

        const angle = (index - 1) * (2 * Math.PI / (total - 1));
        return {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle)
        };
    };

    if (loading) {
        return (
            <div className="topology-loading">
                <RefreshCw className="spin" />
                <p>Mapping Neural Network Topology...</p>
            </div>
        );
    }

    return (
        <div className="topology-container fade-in">
            <header className="topology-header">
                <div className="title-group">
                    <h2><Globe className="text-blue" /> Live Network Topology</h2>
                    <p>Visual map of all endpoints and their security integrity status</p>
                </div>
                <div className="topology-legend">
                    <span className="legend-item"><span className="dot online"></span> Secure</span>
                    <span className="legend-item"><span className="dot isolated"></span> Isolated</span>
                    <span className="legend-item"><span className="dot warning"></span> At Risk</span>
                </div>
                <button className="cyber-button secondary" onClick={fetchTopology}>
                    <RefreshCw size={16} /> Refresh Map
                </button>
            </header>

            <div className="topology-viz-layout">
                <div className="svg-container">
                    <svg viewBox="0 0 800 700" className="topology-svg">
                        {/* Define gradients */}
                        <defs>
                            <radialGradient id="gateway-glow" cx="50%" cy="50%" r="50%" fx="50%" fy="50%">
                                <stop offset="0%" stopColor="rgba(59, 130, 246, 0.4)" />
                                <stop offset="100%" stopColor="rgba(59, 130, 246, 0)" />
                            </radialGradient>
                        </defs>

                        {/* Connection Lines */}
                        {data?.nodes?.length > 1 && data.nodes.slice(1).map((node, i) => {
                            const { x, y } = getCoordinates(i + 1, data?.nodes?.length || 0);
                            return (
                                <line
                                    key={`link-${i}`}
                                    x1="400" y1="350"
                                    x2={x} y2={y}
                                    className={`topology-link ${node.status}`}
                                />
                            );
                        })}

                        {/* Pulse Ring for Gateway */}
                        <circle cx="400" cy="350" r="60" fill="url(#gateway-glow)" className="pulse-slow" />

                        {/* Nodes */}
                        {data?.nodes?.map((node, i) => {
                            const { x, y } = getCoordinates(i, data?.nodes?.length || 0);
                            const isGateway = node.type === 'gateway';

                            return (
                                <g
                                    key={node.id}
                                    className={`node-group ${isGateway ? 'gateway' : 'endpoint'} ${node.status} ${selectedNode?.id === node.id ? 'selected' : ''}`}
                                    onClick={() => setSelectedNode(node)}
                                >
                                    <circle cx={x} cy={y} r={isGateway ? 35 : 28} className="node-bg" />
                                    <foreignObject x={x - 15} y={y - 15} width="30" height="30">
                                        <div className="node-icon-wrapper">
                                            {isGateway ? <Globe color="#fff" size={20} /> : <Monitor color="#fff" size={18} />}
                                        </div>
                                    </foreignObject>
                                    <text x={x} y={y + 50} textAnchor="middle" className="node-label">
                                        {node.label}
                                    </text>
                                    {node.risk === 'critical' && (
                                        <circle cx={x + 18} cy={y - 18} r="10" className="risk-indicator pulse-fast" />
                                    )}
                                </g>
                            );
                        })}
                    </svg>
                </div>

                <div className="topology-sidebar">
                    <div className="card-glass info-card">
                        <h3><Info size={18} /> Node Intel</h3>
                        {selectedNode ? (
                            <div className="node-details">
                                <div className="detail-row">
                                    <span className="label">Hostname:</span>
                                    <span className="value">{selectedNode.label}</span>
                                </div>
                                <div className="detail-row">
                                    <span className="label">Type:</span>
                                    <span className="value text-capitalize">{selectedNode.type}</span>
                                </div>
                                <div className="detail-row">
                                    <span className="label">Status:</span>
                                    <span className={`value status-text ${selectedNode.status}`}>{selectedNode.status.toUpperCase()}</span>
                                </div>
                                {selectedNode.risk && (
                                    <div className="detail-row">
                                        <span className="label">Risk Level:</span>
                                        <span className={`value risk-badge ${selectedNode.risk}`}>{selectedNode.risk.toUpperCase()}</span>
                                    </div>
                                )}
                                <div className="detail-actions">
                                    {selectedNode.type === 'endpoint' && (
                                        <button className="cyber-button mini primary">INSPECT ASSET</button>
                                    )}
                                </div>
                            </div>
                        ) : (
                            <p className="no-selection">Select a node to view connectivity intelligence</p>
                        )}
                    </div>

                    <div className="card-glass stats-card">
                        <h3><Activity size={18} /> Topology Health</h3>
                        <div className="topology-stats">
                            <div className="stat-item">
                                <span className="stat-label">Total Assets</span>
                                <span className="stat-value">{(data?.nodes?.length || 1) - 1}</span>
                            </div>
                            <div className="stat-item">
                                <span className="stat-label">Isolated</span>
                                <span className="stat-value text-orange">
                                    {data?.nodes?.filter(n => n.status === 'isolated').length || 0}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default NetworkTopology;
