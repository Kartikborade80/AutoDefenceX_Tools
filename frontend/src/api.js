import axios from 'axios';

// Helper to get API URL
const getApiUrl = () => {
    if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
    // If on localhost (dev), assume backend is on 8000
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        return 'http://localhost:8000';
    }
    // In production (Render), backend is on same origin, so use relative path
    return '';
};

const API_URL = getApiUrl();

const api = axios.create({
    baseURL: API_URL,
    headers: {
        // 'Content-Type': 'application/json', // Let axios set this automatically
    },
});

// Add interceptor for auth token if needed later
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

// Add interceptor to handle 401 Unauthorized errors
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response && error.response.status === 401) {
            // Token expired or invalid
            localStorage.removeItem('token');
            // Redirect to login page
            if (window.location.pathname !== '/login') {
                window.location.href = '/login';
            }
        }
        return Promise.reject(error);
    }
);

export default api;
