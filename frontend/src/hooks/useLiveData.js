import { useState, useEffect } from 'react';

/**
 * Custom hook for polling live data at specified intervals
 * @param {Function} fetchFunction - Async function that fetches the data
 * @param {number} interval - Polling interval in milliseconds (default: 5000ms)
 * @returns {Object} - { data, loading, error, refetch }
 */
export const useLiveData = (fetchFunction, interval = 5000) => {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchData = async () => {
        try {
            const result = await fetchFunction();
            setData(result);
            setError(null);
        } catch (err) {
            setError(err);
            console.error('Live data fetch error:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        // Initial fetch
        fetchData();

        // Set up polling interval
        const intervalId = setInterval(fetchData, interval);

        // Cleanup on unmount
        return () => clearInterval(intervalId);
    }, [interval]); // Re-run if interval changes

    return { data, loading, error, refetch: fetchData };
};

export default useLiveData;
