import { useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

const UserActivityHandler = ({ isAuthenticated, onLogout }) => {
    const navigate = useNavigate();
    const timeoutRef = useRef(null);
    const INACTIVITY_LIMIT = 15 * 60 * 1000; // 15 minutes

    const resetTimer = useCallback(() => {
        if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
        }

        if (isAuthenticated) {
            timeoutRef.current = setTimeout(() => {
                console.log("Inactivity detected. Auto-logging out...");
                onLogout();
                navigate('/login?reason=inactivity');
            }, INACTIVITY_LIMIT);
        }
    }, [isAuthenticated, onLogout, navigate]);

    useEffect(() => {
        // Events to track for activity
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];

        if (isAuthenticated) {
            resetTimer();
            events.forEach(event => {
                window.addEventListener(event, resetTimer);
            });
        }

        return () => {
            if (timeoutRef.current) {
                clearTimeout(timeoutRef.current);
            }
            events.forEach(event => {
                window.removeEventListener(event, resetTimer);
            });
        };
    }, [isAuthenticated, resetTimer]);

    return null; // This component doesn't render anything
};

export default UserActivityHandler;
