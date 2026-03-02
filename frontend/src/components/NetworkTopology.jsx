import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from '../api';
import {
    Globe, Monitor, Save, Trash2, ZoomIn, ZoomOut, Maximize2,
    Grid3x3, Link2, MousePointer, RefreshCw, Download, Plus,
    X, Server, Wifi, Shield, Cloud, Router as RouterIcon, Laptop,
    Cpu, Settings, ChevronRight, CheckCircle, AlertCircle, Move
} from 'lucide-react';
import './NetworkTopology.css';

// ====== DEVICE TYPE DEFINITIONS ======
const DEVICE_TYPES = [
    { type: 'router', label: 'Router', color: '#3b82f6', icon: '🔄', defaultPorts: 4 },
    { type: 'switch', label: 'Switch', color: '#10b981', icon: '🔌', defaultPorts: 8 },
    { type: 'server', label: 'Server', color: '#8b5cf6', icon: '🖥️', defaultPorts: 2 },
    { type: 'firewall', label: 'Firewall', color: '#ef4444', icon: '🔥', defaultPorts: 2 },
    { type: 'wifi', label: 'Wi-Fi AP', color: '#f59e0b', icon: '📶', defaultPorts: 1 },
    { type: 'pc', label: 'PC', color: '#06b6d4', icon: '💻', defaultPorts: 1 },
    { type: 'laptop', label: 'Laptop', color: '#14b8a6', icon: '💻', defaultPorts: 1 },
    { type: 'cloud', label: 'Cloud', color: '#64748b', icon: '☁️', defaultPorts: 2 },
];

// ====== SVG DEVICE ICONS ======
const DeviceIcon = ({ type, size = 28 }) => {
    const s = size;
    const h = s / 2;
    switch (type) {
        case 'router':
            return (
                <g>
                    <circle cx={h} cy={h} r={h - 2} fill="none" stroke="#3b82f6" strokeWidth="2" />
                    <path d={`M${h - 6},${h} L${h + 6},${h} M${h},${h - 6} L${h},${h + 6}`} stroke="#3b82f6" strokeWidth="2" />
                    <path d={`M${h + 4},${h - 4} L${h + 6},${h - 6}`} stroke="#3b82f6" strokeWidth="1.5" />
                    <circle cx={h} cy={h} r="3" fill="#3b82f6" />
                </g>
            );
        case 'switch':
            return (
                <g>
                    <rect x="2" y={h - 5} width={s - 4} height="10" rx="2" fill="none" stroke="#10b981" strokeWidth="1.5" />
                    {[0.25, 0.4, 0.55, 0.7].map((p, i) => (
                        <circle key={i} cx={s * p} cy={h} r="2" fill="#10b981" />
                    ))}
                </g>
            );
        case 'server':
            return (
                <g>
                    <rect x="4" y="3" width={s - 8} height={s / 3 - 1} rx="2" fill="none" stroke="#8b5cf6" strokeWidth="1.5" />
                    <rect x="4" y={s / 3 + 2} width={s - 8} height={s / 3 - 1} rx="2" fill="none" stroke="#8b5cf6" strokeWidth="1.5" />
                    <rect x="4" y={2 * s / 3 + 1} width={s - 8} height={s / 3 - 1} rx="2" fill="none" stroke="#8b5cf6" strokeWidth="1.5" />
                    <circle cx={s - 8} cy={s / 6 + 1} r="1.5" fill="#10b981" />
                    <circle cx={s - 8} cy={s / 2 + 1} r="1.5" fill="#10b981" />
                    <circle cx={s - 8} cy={5 * s / 6 + 1} r="1.5" fill="#f59e0b" />
                </g>
            );
        case 'firewall':
            return (
                <g>
                    <rect x="3" y="3" width={s - 6} height={s - 6} rx="3" fill="none" stroke="#ef4444" strokeWidth="1.5" />
                    <line x1="3" y1={h} x2={s - 3} y2={h} stroke="#ef4444" strokeWidth="1" strokeDasharray="2,2" />
                    <path d={`M${h},6 L${h + 4},${h - 2} L${h},${h + 2} L${h - 4},${h - 2} Z`} fill="#ef4444" opacity="0.6" />
                </g>
            );
        case 'wifi':
            return (
                <g>
                    <path d={`M${h - 10},${h - 2} Q${h},${h - 12} ${h + 10},${h - 2}`} fill="none" stroke="#f59e0b" strokeWidth="1.5" />
                    <path d={`M${h - 7},${h + 1} Q${h},${h - 6} ${h + 7},${h + 1}`} fill="none" stroke="#f59e0b" strokeWidth="1.5" />
                    <path d={`M${h - 4},${h + 4} Q${h},${h - 1} ${h + 4},${h + 4}`} fill="none" stroke="#f59e0b" strokeWidth="1.5" />
                    <circle cx={h} cy={h + 6} r="2" fill="#f59e0b" />
                </g>
            );
        case 'pc':
            return (
                <g>
                    <rect x="4" y="3" width={s - 8} height={s * 0.55} rx="2" fill="none" stroke="#06b6d4" strokeWidth="1.5" />
                    <line x1={h - 4} y1={s * 0.58 + 3} x2={h + 4} y2={s * 0.58 + 3} stroke="#06b6d4" strokeWidth="2" />
                    <line x1={h} y1={s * 0.55 + 3} x2={h} y2={s * 0.58 + 3} stroke="#06b6d4" strokeWidth="1.5" />
                    <rect x={h - 6} y={s * 0.58 + 4} width="12" height="3" rx="1" fill="none" stroke="#06b6d4" strokeWidth="1" />
                </g>
            );
        case 'laptop':
            return (
                <g>
                    <rect x="5" y="4" width={s - 10} height={s * 0.5} rx="2" fill="none" stroke="#14b8a6" strokeWidth="1.5" />
                    <path d={`M3,${s * 0.55 + 4} L${s - 3},${s * 0.55 + 4} L${s - 1},${s * 0.7 + 2} L1,${s * 0.7 + 2} Z`} fill="none" stroke="#14b8a6" strokeWidth="1.5" />
                </g>
            );
        case 'cloud':
            return (
                <g>
                    <path d={`M${h - 8},${h + 4} A6,6 0 0,1 ${h - 4},${h - 5} A7,7 0 0,1 ${h + 7},${h - 3} A5,5 0 0,1 ${h + 8},${h + 4} Z`}
                        fill="none" stroke="#64748b" strokeWidth="1.5" />
                </g>
            );
        default:
            return <circle cx={h} cy={h} r={h - 2} fill="none" stroke="#fff" strokeWidth="1.5" />;
    }
};

// ====== GENERATE UNIQUE ID ======
let idCounter = 0;
const genId = () => `dev_${Date.now()}_${++idCounter}`;
const connId = () => `conn_${Date.now()}_${++idCounter}`;

// ====== MAIN COMPONENT ======
const NetworkTopology = () => {
    // Canvas state
    const [viewBox, setViewBox] = useState({ x: -200, y: -100, w: 1200, h: 800 });
    const [isPanning, setIsPanning] = useState(false);
    const [panStart, setPanStart] = useState({ x: 0, y: 0 });
    const [showGrid, setShowGrid] = useState(true);

    // Device & connection state
    const [devices, setDevices] = useState([]);
    const [connections, setConnections] = useState([]);
    const [selectedDevice, setSelectedDevice] = useState(null);
    const [selectedConnection, setSelectedConnection] = useState(null);

    // Interaction modes
    const [mode, setMode] = useState('select'); // 'select', 'connect', 'place'
    const [placingType, setPlacingType] = useState(null);
    const [connectFrom, setConnectFrom] = useState(null);

    // Drag state
    const [dragging, setDragging] = useState(null);
    const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

    // UI state
    const [saveStatus, setSaveStatus] = useState(null);
    const [loading, setLoading] = useState(true);
    const [undoStack, setUndoStack] = useState([]);

    const svgRef = useRef(null);

    // ====== SAVE UNDO STATE ======
    const pushUndo = useCallback(() => {
        setUndoStack(prev => [...prev.slice(-20), { devices: [...devices], connections: [...connections] }]);
    }, [devices, connections]);

    // ====== LOAD TOPOLOGY ======
    useEffect(() => {
        const loadTopology = async () => {
            try {
                const token = localStorage.getItem('token');
                const res = await axios.get('/topology/load', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                if (res.data.success && res.data.topology?.data) {
                    const data = res.data.topology.data;
                    setDevices(data.devices || []);
                    setConnections(data.connections || []);
                }
            } catch (e) {
                console.error('Failed to load topology:', e);
            } finally {
                setLoading(false);
            }
        };
        loadTopology();
    }, []);

    // ====== SAVE TOPOLOGY ======
    const saveTopology = async () => {
        setSaveStatus('saving');
        try {
            const token = localStorage.getItem('token');
            await axios.post('/topology/save', {
                name: 'Network Topology',
                topology_data: { devices, connections }
            }, { headers: { Authorization: `Bearer ${token}` } });
            setSaveStatus('saved');
            setTimeout(() => setSaveStatus(null), 2000);
        } catch (e) {
            console.error('Save failed:', e);
            setSaveStatus('error');
            setTimeout(() => setSaveStatus(null), 3000);
        }
    };

    // ====== SVG COORDINATE CONVERSION ======
    const getSVGCoords = useCallback((e) => {
        const svg = svgRef.current;
        if (!svg) return { x: 0, y: 0 };
        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const converted = pt.matrixTransform(svg.getScreenCTM().inverse());
        return { x: converted.x, y: converted.y };
    }, []);

    // ====== CANVAS: Mouse Down ======
    const handleCanvasMouseDown = (e) => {
        if (e.target === svgRef.current || e.target.classList.contains('grid-bg')) {
            if (e.button === 1 || (e.button === 0 && e.altKey)) {
                // Middle-click or Alt+click: Pan
                setIsPanning(true);
                setPanStart({ x: e.clientX, y: e.clientY });
                e.preventDefault();
            } else if (mode === 'place' && placingType) {
                // Place new device
                const coords = getSVGCoords(e);
                pushUndo();
                const devType = DEVICE_TYPES.find(d => d.type === placingType);
                const newDevice = {
                    id: genId(),
                    type: placingType,
                    x: coords.x - 30,
                    y: coords.y - 30,
                    hostname: `${devType?.label || 'Device'}-${devices.length + 1}`,
                    ip: '',
                    subnet: '255.255.255.0',
                    mac: '',
                    gateway: '',
                    vlan: '',
                    ssid: '',
                    channel: '',
                    security: 'WPA2',
                    services: '',
                    provider: '',
                    region: '',
                    portCount: devType?.defaultPorts || 1,
                    status: 'active'
                };
                setDevices(prev => [...prev, newDevice]);
                setSelectedDevice(newDevice);
                setMode('select');
                setPlacingType(null);
            } else if (mode === 'select') {
                setSelectedDevice(null);
                setSelectedConnection(null);
            }
        }
    };

    // ====== CANVAS: Mouse Move ======
    const handleCanvasMouseMove = (e) => {
        if (isPanning) {
            const dx = (e.clientX - panStart.x) * (viewBox.w / svgRef.current?.clientWidth || 1);
            const dy = (e.clientY - panStart.y) * (viewBox.h / svgRef.current?.clientHeight || 1);
            setViewBox(prev => ({ ...prev, x: prev.x - dx, y: prev.y - dy }));
            setPanStart({ x: e.clientX, y: e.clientY });
        }
        if (dragging) {
            const coords = getSVGCoords(e);
            setDevices(prev => prev.map(d =>
                d.id === dragging ? { ...d, x: coords.x - dragOffset.x, y: coords.y - dragOffset.y } : d
            ));
        }
    };

    // ====== CANVAS: Mouse Up ======
    const handleCanvasMouseUp = () => {
        setIsPanning(false);
        if (dragging) {
            setDragging(null);
        }
    };

    // ====== CANVAS: Wheel Zoom ======
    const handleWheel = (e) => {
        e.preventDefault();
        const scaleFactor = e.deltaY > 0 ? 1.1 : 0.9;
        const svg = svgRef.current;
        if (!svg) return;

        const pt = svg.createSVGPoint();
        pt.x = e.clientX;
        pt.y = e.clientY;
        const cursor = pt.matrixTransform(svg.getScreenCTM().inverse());

        setViewBox(prev => {
            const newW = prev.w * scaleFactor;
            const newH = prev.h * scaleFactor;
            const newX = cursor.x - (cursor.x - prev.x) * scaleFactor;
            const newY = cursor.y - (cursor.y - prev.y) * scaleFactor;
            return { x: newX, y: newY, w: Math.max(200, Math.min(5000, newW)), h: Math.max(150, Math.min(3750, newH)) };
        });
    };

    // ====== DEVICE: Click ======
    const handleDeviceClick = (e, device) => {
        e.stopPropagation();
        if (mode === 'connect') {
            if (!connectFrom) {
                setConnectFrom(device.id);
            } else if (connectFrom !== device.id) {
                // Create connection
                const alreadyConnected = connections.some(c =>
                    (c.from === connectFrom && c.to === device.id) ||
                    (c.from === device.id && c.to === connectFrom)
                );
                if (!alreadyConnected) {
                    pushUndo();
                    setConnections(prev => [...prev, {
                        id: connId(),
                        from: connectFrom,
                        to: device.id,
                        linkType: 'ethernet',
                        bandwidth: '1 Gbps',
                        status: 'active'
                    }]);
                }
                setConnectFrom(null);
            }
        } else {
            setSelectedDevice(device);
            setSelectedConnection(null);
        }
    };

    // ====== DEVICE: Start Drag ======
    const handleDeviceMouseDown = (e, device) => {
        if (mode === 'select') {
            e.stopPropagation();
            const coords = getSVGCoords(e);
            pushUndo();
            setDragging(device.id);
            setDragOffset({ x: coords.x - device.x, y: coords.y - device.y });
            setSelectedDevice(device);
            setSelectedConnection(null);
        }
    };

    // ====== DELETE DEVICE ======
    const deleteDevice = (deviceId) => {
        pushUndo();
        setDevices(prev => prev.filter(d => d.id !== deviceId));
        setConnections(prev => prev.filter(c => c.from !== deviceId && c.to !== deviceId));
        if (selectedDevice?.id === deviceId) setSelectedDevice(null);
    };

    // ====== DELETE CONNECTION ======
    const deleteConnection = (connIdStr) => {
        pushUndo();
        setConnections(prev => prev.filter(c => c.id !== connIdStr));
        setSelectedConnection(null);
    };

    // ====== UNDO ======
    const undo = () => {
        if (undoStack.length === 0) return;
        const last = undoStack[undoStack.length - 1];
        setDevices(last.devices);
        setConnections(last.connections);
        setUndoStack(prev => prev.slice(0, -1));
    };

    // ====== CLEAR ALL ======
    const clearAll = () => {
        if (devices.length === 0) return;
        pushUndo();
        setDevices([]);
        setConnections([]);
        setSelectedDevice(null);
        setSelectedConnection(null);
    };

    // ====== ZOOM CONTROLS ======
    const zoomIn = () => setViewBox(prev => ({ ...prev, w: prev.w * 0.85, h: prev.h * 0.85 }));
    const zoomOut = () => setViewBox(prev => ({ ...prev, w: prev.w * 1.15, h: prev.h * 1.15 }));
    const fitAll = () => {
        if (devices.length === 0) {
            setViewBox({ x: -200, y: -100, w: 1200, h: 800 });
            return;
        }
        const xs = devices.map(d => d.x);
        const ys = devices.map(d => d.y);
        const minX = Math.min(...xs) - 100;
        const maxX = Math.max(...xs) + 160;
        const minY = Math.min(...ys) - 100;
        const maxY = Math.max(...ys) + 160;
        setViewBox({ x: minX, y: minY, w: maxX - minX, h: maxY - minY });
    };

    // ====== UPDATE DEVICE PROPERTY ======
    const updateDeviceProp = (key, value) => {
        if (!selectedDevice) return;
        setDevices(prev => prev.map(d => d.id === selectedDevice.id ? { ...d, [key]: value } : d));
        setSelectedDevice(prev => ({ ...prev, [key]: value }));
    };

    // ====== EXPORT CANVAS AS PNG ======
    const exportAsImage = () => {
        const svg = svgRef.current;
        if (!svg) return;
        const serializer = new XMLSerializer();
        const svgStr = serializer.serializeToString(svg);
        const canvas = document.createElement('canvas');
        canvas.width = 1920;
        canvas.height = 1080;
        const ctx = canvas.getContext('2d');
        const img = new Image();
        const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        img.onload = () => {
            ctx.fillStyle = '#0f172a';
            ctx.fillRect(0, 0, 1920, 1080);
            ctx.drawImage(img, 0, 0, 1920, 1080);
            const a = document.createElement('a');
            a.download = 'network-topology.png';
            a.href = canvas.toDataURL('image/png');
            a.click();
            URL.revokeObjectURL(url);
        };
        img.src = url;
    };


    // ====== CONNECTION LINE ======
    const ConnectionLine = ({ conn }) => {
        const fromDev = devices.find(d => d.id === conn.from);
        const toDev = devices.find(d => d.id === conn.to);
        if (!fromDev || !toDev) return null;

        const x1 = fromDev.x + 30, y1 = fromDev.y + 30;
        const x2 = toDev.x + 30, y2 = toDev.y + 30;
        const isSelected = selectedConnection?.id === conn.id;
        const statusColor = conn.status === 'active' ? '#10b981' : conn.status === 'down' ? '#ef4444' : '#f59e0b';

        return (
            <g onClick={(e) => { e.stopPropagation(); setSelectedConnection(conn); setSelectedDevice(null); }}
                style={{ cursor: 'pointer' }}>
                {/* Hit area */}
                <line x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke="transparent" strokeWidth="14" />
                {/* Visible line */}
                <line x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke={isSelected ? '#3b82f6' : statusColor}
                    strokeWidth={isSelected ? 3 : 2}
                    strokeDasharray={conn.linkType === 'wireless' ? '6,4' : 'none'}
                    opacity={0.7} />
                {/* Data flow animation */}
                {conn.status === 'active' && (
                    <circle r="3" fill={statusColor} opacity="0.9">
                        <animateMotion dur="2s" repeatCount="indefinite"
                            path={`M${x1},${y1} L${x2},${y2}`} />
                    </circle>
                )}
                {/* Bandwidth label */}
                <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 8}
                    fill="#64748b" fontSize="9" textAnchor="middle"
                    style={{ pointerEvents: 'none' }}>
                    {conn.bandwidth || ''}
                </text>
            </g>
        );
    };

    // ====== DEVICE NODE ======
    const DeviceNode = ({ device }) => {
        const devType = DEVICE_TYPES.find(d => d.type === device.type);
        const isSelected = selectedDevice?.id === device.id;
        const isConnectSource = connectFrom === device.id;

        return (
            <g transform={`translate(${device.x}, ${device.y})`}
                onMouseDown={(e) => handleDeviceMouseDown(e, device)}
                onClick={(e) => handleDeviceClick(e, device)}
                style={{ cursor: mode === 'connect' ? 'crosshair' : 'grab' }}>

                {/* Selection glow */}
                {isSelected && (
                    <rect x="-6" y="-6" width="72" height="72" rx="18"
                        fill="none" stroke="#3b82f6" strokeWidth="2"
                        filter="url(#glow)" opacity="0.8" />
                )}

                {/* Connect source indicator */}
                {isConnectSource && (
                    <rect x="-6" y="-6" width="72" height="72" rx="18"
                        fill="none" stroke="#f59e0b" strokeWidth="2.5"
                        strokeDasharray="4,3">
                        <animate attributeName="stroke-dashoffset" from="0" to="14" dur="0.8s" repeatCount="indefinite" />
                    </rect>
                )}

                {/* Background */}
                <rect width="60" height="60" rx="14"
                    fill={`${devType?.color || '#334155'}15`}
                    stroke={devType?.color || '#334155'}
                    strokeWidth={isSelected ? 2.5 : 1.5} />

                {/* Status dot */}
                <circle cx="52" cy="8" r="4"
                    fill={device.status === 'active' ? '#10b981' : device.status === 'down' ? '#ef4444' : '#f59e0b'} />

                {/* Device Icon */}
                <g transform="translate(16, 10)">
                    <DeviceIcon type={device.type} size={28} />
                </g>

                {/* Label */}
                <text x="30" y="75" textAnchor="middle"
                    fill="#e2e8f0" fontSize="10" fontWeight="500"
                    style={{ pointerEvents: 'none' }}>
                    {device.hostname.length > 12 ? device.hostname.slice(0, 12) + '...' : device.hostname}
                </text>

                {/* IP Label */}
                {device.ip && (
                    <text x="30" y="87" textAnchor="middle"
                        fill="#64748b" fontSize="8"
                        style={{ pointerEvents: 'none' }}>
                        {device.ip}
                    </text>
                )}
            </g>
        );
    };

    // ====== RENDER PROPERTIES BY DEVICE TYPE ======
    const renderDeviceProperties = () => {
        if (!selectedDevice) return null;
        const dev = selectedDevice;
        const formFields = [
            { key: 'hostname', label: 'Hostname', type: 'text' },
            { key: 'ip', label: 'IP Address', type: 'text', placeholder: '192.168.1.1' },
            { key: 'subnet', label: 'Subnet Mask', type: 'text', placeholder: '255.255.255.0' },
            { key: 'gateway', label: 'Gateway', type: 'text', placeholder: '192.168.1.1' },
            { key: 'mac', label: 'MAC Address', type: 'text', placeholder: 'AA:BB:CC:DD:EE:FF' },
        ];

        // Conditional fields based on device type
        if (dev.type === 'switch') {
            formFields.push({ key: 'vlan', label: 'VLAN ID', type: 'text', placeholder: '10' });
            formFields.push({ key: 'portCount', label: 'Port Count', type: 'number' });
        }
        if (dev.type === 'wifi') {
            formFields.push({ key: 'ssid', label: 'SSID', type: 'text', placeholder: 'Company-WiFi' });
            formFields.push({ key: 'channel', label: 'Channel', type: 'text', placeholder: '6' });
            formFields.push({ key: 'security', label: 'Security', type: 'text', placeholder: 'WPA2' });
        }
        if (dev.type === 'server') {
            formFields.push({ key: 'services', label: 'Services', type: 'text', placeholder: 'HTTP, SSH, DNS' });
        }
        if (dev.type === 'cloud') {
            formFields.push({ key: 'provider', label: 'Provider', type: 'text', placeholder: 'AWS' });
            formFields.push({ key: 'region', label: 'Region', type: 'text', placeholder: 'ap-south-1' });
        }

        return formFields.map(f => (
            <div className="prop-field" key={f.key}>
                <label>{f.label}</label>
                <input
                    type={f.type || 'text'}
                    value={dev[f.key] || ''}
                    placeholder={f.placeholder || ''}
                    onChange={(e) => updateDeviceProp(f.key, e.target.value)}
                />
            </div>
        ));
    };

    if (loading) {
        return (
            <div className="topo-loading">
                <RefreshCw className="spin" size={32} />
                <p>Loading Topology Map...</p>
            </div>
        );
    }

    return (
        <div className="topo-designer">
            {/* ====== TOP TOOLBAR ====== */}
            <div className="topo-toolbar">
                <div className="toolbar-left">
                    <Globe size={20} className="toolbar-logo" />
                    <h2>Network Topology Designer</h2>
                </div>
                <div className="toolbar-center">
                    <button className={`tool-btn ${mode === 'select' ? 'active' : ''}`}
                        onClick={() => { setMode('select'); setPlacingType(null); setConnectFrom(null); }}
                        title="Select & Move (V)">
                        <MousePointer size={16} />
                    </button>
                    <button className={`tool-btn ${mode === 'connect' ? 'active' : ''}`}
                        onClick={() => { setMode('connect'); setPlacingType(null); setConnectFrom(null); }}
                        title="Draw Connection (C)">
                        <Link2 size={16} />
                    </button>
                    <div className="toolbar-divider" />
                    <button className="tool-btn" onClick={undo} title="Undo (Ctrl+Z)" disabled={undoStack.length === 0}>
                        <RefreshCw size={16} style={{ transform: 'scaleX(-1)' }} />
                    </button>
                    <button className="tool-btn" onClick={clearAll} title="Clear All">
                        <Trash2 size={16} />
                    </button>
                    <div className="toolbar-divider" />
                    <button className="tool-btn" onClick={zoomIn} title="Zoom In"><ZoomIn size={16} /></button>
                    <button className="tool-btn" onClick={zoomOut} title="Zoom Out"><ZoomOut size={16} /></button>
                    <button className="tool-btn" onClick={fitAll} title="Fit All"><Maximize2 size={16} /></button>
                    <button className={`tool-btn ${showGrid ? 'active' : ''}`} onClick={() => setShowGrid(!showGrid)} title="Toggle Grid">
                        <Grid3x3 size={16} />
                    </button>
                    <div className="toolbar-divider" />
                    <button className="tool-btn" onClick={exportAsImage} title="Export as PNG">
                        <Download size={16} />
                    </button>
                </div>
                <div className="toolbar-right">
                    <button className={`save-btn ${saveStatus || ''}`} onClick={saveTopology} disabled={saveStatus === 'saving'}>
                        {saveStatus === 'saving' ? <RefreshCw size={14} className="spin" /> :
                            saveStatus === 'saved' ? <CheckCircle size={14} /> :
                                saveStatus === 'error' ? <AlertCircle size={14} /> :
                                    <Save size={14} />}
                        {saveStatus === 'saving' ? 'Saving...' : saveStatus === 'saved' ? 'Saved!' : saveStatus === 'error' ? 'Error' : 'Save Map'}
                    </button>
                </div>
            </div>

            <div className="topo-workspace">
                {/* ====== LEFT: DEVICE PALETTE ====== */}
                <div className="device-palette">
                    <div className="palette-header">
                        <Plus size={14} />
                        <span>Devices</span>
                    </div>
                    {DEVICE_TYPES.map(dt => (
                        <button
                            key={dt.type}
                            className={`palette-item ${placingType === dt.type ? 'placing' : ''}`}
                            onClick={() => {
                                setMode('place');
                                setPlacingType(dt.type);
                                setConnectFrom(null);
                            }}
                            title={`Place ${dt.label}`}
                        >
                            <span className="palette-icon" style={{ color: dt.color }}>{dt.icon}</span>
                            <span className="palette-label">{dt.label}</span>
                        </button>
                    ))}
                    <div className="palette-footer">
                        <span className="device-count">{devices.length} devices</span>
                        <span className="conn-count">{connections.length} links</span>
                    </div>
                </div>

                {/* ====== CENTER: SVG CANVAS ====== */}
                <div className="canvas-container"
                    onWheel={handleWheel}
                    onContextMenu={e => e.preventDefault()}>

                    {/* Mode indicator */}
                    {mode !== 'select' && (
                        <div className="mode-indicator">
                            {mode === 'connect' ? (
                                <><Link2 size={14} /> {connectFrom ? 'Click target device' : 'Click source device'}</>
                            ) : (
                                <><Plus size={14} /> Click canvas to place {DEVICE_TYPES.find(d => d.type === placingType)?.label}</>
                            )}
                            <button className="mode-cancel" onClick={() => { setMode('select'); setPlacingType(null); setConnectFrom(null); }}>
                                <X size={12} /> Cancel
                            </button>
                        </div>
                    )}

                    <svg
                        ref={svgRef}
                        viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
                        className="topo-svg"
                        onMouseDown={handleCanvasMouseDown}
                        onMouseMove={handleCanvasMouseMove}
                        onMouseUp={handleCanvasMouseUp}
                        onMouseLeave={handleCanvasMouseUp}
                    >
                        <defs>
                            <filter id="glow">
                                <feGaussianBlur stdDeviation="3" result="blur" />
                                <feMerge>
                                    <feMergeNode in="blur" />
                                    <feMergeNode in="SourceGraphic" />
                                </feMerge>
                            </filter>
                            <pattern id="grid-dots" width="30" height="30" patternUnits="userSpaceOnUse">
                                <circle cx="15" cy="15" r="0.8" fill="rgba(148,163,184,0.15)" />
                            </pattern>
                        </defs>

                        {/* Grid */}
                        {showGrid && (
                            <rect className="grid-bg"
                                x={viewBox.x - 500} y={viewBox.y - 500}
                                width={viewBox.w + 1000} height={viewBox.h + 1000}
                                fill="url(#grid-dots)" />
                        )}

                        {/* Connections */}
                        {connections.map(conn => (
                            <ConnectionLine key={conn.id} conn={conn} />
                        ))}

                        {/* Temporary connection line while connecting */}
                        {connectFrom && (
                            <line
                                x1={devices.find(d => d.id === connectFrom)?.x + 30 || 0}
                                y1={devices.find(d => d.id === connectFrom)?.y + 30 || 0}
                                x2={devices.find(d => d.id === connectFrom)?.x + 30 || 0}
                                y2={devices.find(d => d.id === connectFrom)?.y + 30 || 0}
                                stroke="#f59e0b" strokeWidth="2" strokeDasharray="5,5"
                                opacity="0.5" style={{ pointerEvents: 'none' }}
                            />
                        )}

                        {/* Devices */}
                        {devices.map(device => (
                            <DeviceNode key={device.id} device={device} />
                        ))}

                        {/* Empty state */}
                        {devices.length === 0 && (
                            <g>
                                <text x={viewBox.x + viewBox.w / 2} y={viewBox.y + viewBox.h / 2 - 20}
                                    textAnchor="middle" fill="#475569" fontSize="16" fontWeight="500">
                                    Click a device from the left palette, then click here to place it
                                </text>
                                <text x={viewBox.x + viewBox.w / 2} y={viewBox.y + viewBox.h / 2 + 10}
                                    textAnchor="middle" fill="#334155" fontSize="12">
                                    Use the Connect tool to draw links between devices
                                </text>
                            </g>
                        )}
                    </svg>
                </div>

                {/* ====== RIGHT: PROPERTIES PANEL ====== */}
                <div className="properties-panel">
                    {selectedDevice ? (
                        <>
                            <div className="panel-header">
                                <Settings size={14} />
                                <span>Device Properties</span>
                                <button className="panel-close" onClick={() => setSelectedDevice(null)}>
                                    <X size={14} />
                                </button>
                            </div>
                            <div className="panel-device-badge" style={{ borderLeftColor: DEVICE_TYPES.find(d => d.type === selectedDevice.type)?.color }}>
                                <span className="badge-icon">
                                    {DEVICE_TYPES.find(d => d.type === selectedDevice.type)?.icon}
                                </span>
                                <span className="badge-type">{DEVICE_TYPES.find(d => d.type === selectedDevice.type)?.label}</span>
                            </div>

                            <div className="prop-field">
                                <label>Status</label>
                                <select value={selectedDevice.status || 'active'}
                                    onChange={(e) => updateDeviceProp('status', e.target.value)}>
                                    <option value="active">🟢 Active</option>
                                    <option value="warning">🟡 Warning</option>
                                    <option value="down">🔴 Down</option>
                                </select>
                            </div>

                            {renderDeviceProperties()}

                            <div className="panel-actions">
                                <button className="prop-delete-btn" onClick={() => deleteDevice(selectedDevice.id)}>
                                    <Trash2 size={14} /> Delete Device
                                </button>
                            </div>
                        </>
                    ) : selectedConnection ? (
                        <>
                            <div className="panel-header">
                                <Link2 size={14} />
                                <span>Link Properties</span>
                                <button className="panel-close" onClick={() => setSelectedConnection(null)}>
                                    <X size={14} />
                                </button>
                            </div>
                            <div className="prop-field">
                                <label>From</label>
                                <input type="text" readOnly
                                    value={devices.find(d => d.id === selectedConnection.from)?.hostname || '?'} />
                            </div>
                            <div className="prop-field">
                                <label>To</label>
                                <input type="text" readOnly
                                    value={devices.find(d => d.id === selectedConnection.to)?.hostname || '?'} />
                            </div>
                            <div className="prop-field">
                                <label>Link Type</label>
                                <select value={selectedConnection.linkType || 'ethernet'}
                                    onChange={(e) => {
                                        setConnections(prev => prev.map(c => c.id === selectedConnection.id ? { ...c, linkType: e.target.value } : c));
                                        setSelectedConnection(prev => ({ ...prev, linkType: e.target.value }));
                                    }}>
                                    <option value="ethernet">Ethernet</option>
                                    <option value="fiber">Fiber</option>
                                    <option value="wireless">Wireless</option>
                                    <option value="serial">Serial</option>
                                </select>
                            </div>
                            <div className="prop-field">
                                <label>Bandwidth</label>
                                <select value={selectedConnection.bandwidth || '1 Gbps'}
                                    onChange={(e) => {
                                        setConnections(prev => prev.map(c => c.id === selectedConnection.id ? { ...c, bandwidth: e.target.value } : c));
                                        setSelectedConnection(prev => ({ ...prev, bandwidth: e.target.value }));
                                    }}>
                                    <option value="10 Mbps">10 Mbps</option>
                                    <option value="100 Mbps">100 Mbps</option>
                                    <option value="1 Gbps">1 Gbps</option>
                                    <option value="10 Gbps">10 Gbps</option>
                                    <option value="40 Gbps">40 Gbps</option>
                                </select>
                            </div>
                            <div className="prop-field">
                                <label>Status</label>
                                <select value={selectedConnection.status || 'active'}
                                    onChange={(e) => {
                                        setConnections(prev => prev.map(c => c.id === selectedConnection.id ? { ...c, status: e.target.value } : c));
                                        setSelectedConnection(prev => ({ ...prev, status: e.target.value }));
                                    }}>
                                    <option value="active">🟢 Active</option>
                                    <option value="warning">🟡 Warning</option>
                                    <option value="down">🔴 Down</option>
                                </select>
                            </div>
                            <div className="panel-actions">
                                <button className="prop-delete-btn" onClick={() => deleteConnection(selectedConnection.id)}>
                                    <Trash2 size={14} /> Delete Link
                                </button>
                            </div>
                        </>
                    ) : (
                        <div className="panel-empty">
                            <div className="panel-empty-icon">
                                <Settings size={28} />
                            </div>
                            <p className="panel-empty-title">No Selection</p>
                            <p className="panel-empty-desc">Click a device or link on the canvas to view and edit its properties</p>
                            <div className="panel-tips">
                                <div className="tip-row"><MousePointer size={12} /> <span>Click to select & drag</span></div>
                                <div className="tip-row"><Link2 size={12} /> <span>Connect mode to draw links</span></div>
                                <div className="tip-row"><span style={{ fontSize: '12px' }}>Alt+Drag</span> <span>Pan the canvas</span></div>
                                <div className="tip-row"><span style={{ fontSize: '12px' }}>Scroll</span> <span>Zoom in/out</span></div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default NetworkTopology;
