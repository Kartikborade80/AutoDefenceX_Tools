import React, { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Loader } from 'lucide-react';
import axios from '../api';
import './ChatbotWidget.css';

const ChatbotWidget = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([
        {
            role: 'assistant',
            content: 'Hi! I\'m Sentra. Ask me anything about using the software, managing users, endpoints, tickets, or security policies!'
        }
    ]);
    const [inputMessage, setInputMessage] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showSuggestions, setShowSuggestions] = useState(true);
    const messagesEndRef = useRef(null);

    // Quick reply suggestions
    const suggestions = [
        "How do I create a new user?",
        "What security policies are available?",
        "How do I submit a ticket?",
        "How to monitor endpoints?",
        "How to assign departments?",
        "What are the login credentials?"
    ];

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const sendMessage = async (messageText = null) => {
        const textToSend = messageText || inputMessage.trim();
        if (!textToSend || isLoading) return;

        setInputMessage('');
        setShowSuggestions(false); // Hide suggestions after first message

        // Add user message to chat
        setMessages(prev => [...prev, { role: 'user', content: textToSend }]);
        setIsLoading(true);

        try {
            // Call backend chatbot API
            const response = await axios.post('/chatbot/chat', {
                message: textToSend,
                conversation_history: messages
            });

            // Add AI response to chat
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: response.data.response
            }]);
        } catch (error) {
            console.error('Chatbot error:', error);
            let errorMessage = 'Sorry, I encountered an error. ';

            if (error.response) {
                // Server responded with error
                errorMessage += `Server error: ${error.response.status}. `;
                if (error.response.data?.detail) {
                    errorMessage += error.response.data.detail;
                }
            } else if (error.request) {
                // Request made but no response
                errorMessage += 'No response from server. Please check if backend is running.';
            } else {
                // Something else happened
                errorMessage += error.message;
            }

            setMessages(prev => [...prev, {
                role: 'assistant',
                content: errorMessage
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleSuggestionClick = (suggestion) => {
        sendMessage(suggestion);
    };

    const handleKeyPress = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    };

    return (
        <div className="chatbot-widget">
            {/* Floating Chat Button */}
            {!isOpen && (
                <button
                    className="chatbot-toggle-btn"
                    onClick={() => setIsOpen(true)}
                    title="Ask Sentra"
                >
                    <MessageCircle size={24} />
                    <span className="chatbot-badge">AI</span>
                </button>
            )}

            {/* Chat Window */}
            {isOpen && (
                <div className="chatbot-window">
                    {/* Header */}
                    <div className="chatbot-header">
                        <div className="chatbot-header-info">
                            <MessageCircle size={20} />
                            <div>
                                <h4>Sentra AI</h4>
                                <span className="chatbot-status">● Online</span>
                            </div>
                        </div>
                        <button
                            className="chatbot-close-btn"
                            onClick={() => setIsOpen(false)}
                        >
                            <X size={20} />
                        </button>
                    </div>

                    {/* Messages */}
                    <div className="chatbot-messages">
                        {messages.map((msg, index) => (
                            <div
                                key={index}
                                className={`chatbot-message ${msg.role}`}
                            >
                                <div className="message-content">
                                    {msg.content}
                                </div>
                            </div>
                        ))}
                        {isLoading && (
                            <div className="chatbot-message assistant">
                                <div className="message-content">
                                    <Loader className="spinner" size={16} />
                                    Thinking...
                                </div>
                            </div>
                        )}

                        {/* Quick Reply Suggestions */}
                        {showSuggestions && !isLoading && (
                            <div className="suggestion-chips">
                                <p className="suggestion-label">Quick questions:</p>
                                {suggestions.map((suggestion, index) => (
                                    <button
                                        key={index}
                                        className="suggestion-chip"
                                        onClick={() => handleSuggestionClick(suggestion)}
                                    >
                                        {suggestion}
                                    </button>
                                ))}
                            </div>
                        )}

                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input */}
                    <div className="chatbot-input-container">
                        <input
                            type="text"
                            className="chatbot-input"
                            placeholder="Ask about AutoDefenceX..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            onKeyPress={handleKeyPress}
                            disabled={isLoading}
                        />
                        <button
                            className="chatbot-send-btn"
                            onClick={() => sendMessage()}
                            disabled={isLoading || !inputMessage.trim()}
                        >
                            <Send size={18} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ChatbotWidget;
