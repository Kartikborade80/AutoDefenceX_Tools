import { useEffect, useCallback, useRef } from 'react';

const useWebSockets = (onMessage) => {
    const ws = useRef(null);
    const token = localStorage.getItem('token');

    const connect = useCallback(() => {
        if (!token) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsHost = window.location.host;
        // Adjust host for development if needed
        if (wsHost.includes('5178')) {
            wsHost = 'localhost:8000';
        }

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

        ws.current.onclose = (event) => {
            if (event.code === 1008) {
                console.error('❌ WebSocket Auth Failed. Please login again.');
                return; // Do not reconnect
            }
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
