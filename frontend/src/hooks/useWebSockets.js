import { useEffect, useCallback, useRef } from 'react';

const useWebSockets = (onMessage) => {
    const ws = useRef(null);
    const token = localStorage.getItem('token');

    const connect = useCallback(() => {
        if (!token) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        // Adjust host for development if needed, assuming backend is on same host or 8000
        const wsHost = host.includes('5178') ? 'localhost:8000' : host;

        ws.current = new WebSocket(`${protocol}//${wsHost}/ws/${token}`);

        ws.current.onopen = () => {
            console.log('✅ WebSocket Connected');
        };

        ws.current.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                onMessage(message);
            } catch (error) {
                console.error('WebSocket message error:', error);
            }
        };

        ws.current.onclose = () => {
            console.log('❌ WebSocket Disconnected. Reconnecting...');
            setTimeout(connect, 5000);
        };

        ws.current.onerror = (err) => {
            console.error('WebSocket error:', err);
            ws.current.close();
        };
    }, [token, onMessage]);

    useEffect(() => {
        connect();
        return () => {
            if (ws.current) ws.current.close();
        };
    }, [connect]);

    const sendMessage = (message) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify(message));
        }
    };

    return { sendMessage };
};

export default useWebSockets;
