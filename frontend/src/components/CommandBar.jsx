import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Monitor, User, Ticket, Command, X, ArrowRight } from 'lucide-react';
import api from '../api';
import './CommandBar.css';

const CommandBar = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [results, setResults] = useState([]);
    const [loading, setLoading] = useState(false);
    const [selectedIndex, setSelectedIndex] = useState(0);
    const navigate = useNavigate();
    const inputRef = useRef(null);

    useEffect(() => {
        const handleKeyDown = (e) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                setIsOpen(prev => !prev);
            }
            if (e.key === 'Escape') {
                setIsOpen(false);
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    useEffect(() => {
        if (isOpen && inputRef.current) {
            inputRef.current.focus();
        }
    }, [isOpen]);

    useEffect(() => {
        const fetchResults = async () => {
            if (query.length < 2) {
                setResults([]);
                return;
            }

            setLoading(true);
            try {
                const response = await api.get(`/search/?q=${query}`);
                setResults(response.data.results);
                setSelectedIndex(0);
            } catch (error) {
                console.error("Search error:", error);
            } finally {
                setLoading(false);
            }
        };

        const debounceTimer = setTimeout(fetchResults, 300);
        return () => clearTimeout(debounceTimer);
    }, [query]);

    const handleSelectResult = (result) => {
        setIsOpen(false);
        setQuery('');
        navigate(result.url);
    };

    const handleKeyDown = (e) => {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setSelectedIndex(prev => Math.min(prev + 1, results.length - 1));
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setSelectedIndex(prev => Math.max(prev - 1, 0));
        } else if (e.key === 'Enter' && results[selectedIndex]) {
            handleSelectResult(results[selectedIndex]);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="command-bar-overlay" onClick={() => setIsOpen(false)}>
            <div className="command-bar-modal" onClick={e => e.stopPropagation()} onKeyDown={handleKeyDown}>
                <div className="command-bar-header">
                    <Search className="search-icon" size={20} />
                    <input
                        ref={inputRef}
                        type="text"
                        placeholder="Search for endpoints, users, tickets..."
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                    />
                    <div className="command-hint">ESC</div>
                </div>

                <div className="command-bar-results">
                    {loading ? (
                        <div className="search-status">Searching encrypted databases...</div>
                    ) : results.length > 0 ? (
                        results.map((result, index) => (
                            <div
                                key={result.id}
                                className={`search-result-item ${index === selectedIndex ? 'selected' : ''}`}
                                onClick={() => handleSelectResult(result)}
                                onMouseEnter={() => setSelectedIndex(index)}
                            >
                                <div className="result-icon-wrapper">
                                    {result.category === 'endpoint' && <Monitor size={18} />}
                                    {result.category === 'user' && <User size={18} />}
                                    {result.category === 'ticket' && <Ticket size={18} />}
                                </div>
                                <div className="result-info">
                                    <span className="result-title">{result.title}</span>
                                    <span className="result-subtitle">{result.subtitle}</span>
                                </div>
                                <span className="category-tag">{result.category}</span>
                                <ArrowRight className="arrow-icon" size={14} />
                            </div>
                        ))
                    ) : query.length >= 2 ? (
                        <div className="search-status">No assets found matching "{query}"</div>
                    ) : (
                        <div className="search-placeholder">
                            <p>Try searching for a hostname, IP address, or employee name.</p>
                            <div className="quick-commands">
                                <div className="quick-cmd"><Command size={14} /> + K / CTRL + K to toggle</div>
                                <div className="quick-cmd">↑ ↓ to navigate</div>
                                <div className="quick-cmd">ENTER to jump</div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default CommandBar;
