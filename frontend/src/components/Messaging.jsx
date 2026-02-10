import React, { useState, useEffect, useRef } from 'react';
import api from '../api';
import { Send, User, Users, Building, MessageSquare, Search } from 'lucide-react';
import { useLocation } from 'react-router-dom';

const Messaging = () => {
    const [messages, setMessages] = useState([]);
    const [activeTab, setActiveTab] = useState('personal');
    const [newMessage, setNewMessage] = useState('');
    const [selectedContact, setSelectedContact] = useState(null);
    const [contacts, setContacts] = useState([]);
    const [searchQuery, setSearchQuery] = useState('');
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const messagesEndRef = useRef(null);
    const location = useLocation();

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    const formatMessageTime = (timestamp) => {
        if (!timestamp) return '';

        const msgDate = new Date(timestamp);
        const today = new Date();

        const isToday = msgDate.toDateString() === today.toDateString();

        if (isToday) {
            return msgDate.toLocaleTimeString('en-IN', {
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
            });
        } else {
            return msgDate.toLocaleString('en-IN', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
            });
        }
    };

    const handleSenderClick = (senderId) => {
        if (senderId === userInfo.id) return;

        // Find the contact and select them
        const contact = contacts.find(c => c.id === senderId);
        if (contact) {
            setActiveTab('personal');
            setSelectedContact(contact);
        }
    };

    useEffect(() => {
        fetchContacts();
    }, []);

    // Handle auto-selection from navigation state
    useEffect(() => {
        if (location.state && location.state.openChatWith && contacts.length > 0) {
            const contactId = location.state.openChatWith;
            const contact = contacts.find(c => c.id === contactId);
            if (contact) {
                setActiveTab('personal');
                setSelectedContact(contact);
                // Clear state so it doesn't re-select on every render/tab change
                window.history.replaceState({}, document.title);
            }
        }
    }, [location.state, contacts]);

    const fetchContacts = async () => {
        try {
            const token = localStorage.getItem('token');
            const res = await api.get('/users/active', {
                headers: { Authorization: `Bearer ${token}` }
            });
            setContacts(res.data);
        } catch (err) {
            console.error("Failed to fetch contacts", err);
        }
    };

    const fetchMessages = async () => {
        if (!userInfo || !userInfo.id) {
            console.warn("User info missing, skipping message fetch.");
            return;
        }

        try {
            let endpoint = '';
            if (activeTab === 'personal') endpoint = `/messages/personal/${userInfo.id}`;
            else if (activeTab === 'department') endpoint = `/messages/department/${userInfo.department_id}`;
            else if (activeTab === 'community') endpoint = `/messages/community/${userInfo.organization_id}`;

            const response = await api.get(endpoint);
            setMessages(response.data);
            setTimeout(scrollToBottom, 100);
        } catch (error) {
            console.error("Error fetching messages:", error);
        }
    };

    useEffect(() => {
        if (userInfo && userInfo.id) {
            fetchMessages();
            const interval = setInterval(fetchMessages, 5000);
            return () => clearInterval(interval);
        }
    }, [activeTab, userInfo.id, selectedContact]);

    const handleSendMessage = async (e) => {
        e.preventDefault();

        if (!userInfo || !userInfo.organization_id) {
            console.error("Missing critical user info (Organization ID). Please re-login.");
            return;
        }

        if (!newMessage.trim()) return;

        try {
            let receiverIdNum = null;

            if (activeTab === 'personal') {
                if (!selectedContact) {
                    console.warn("No contact selected for personal message.");
                    return;
                }
                receiverIdNum = selectedContact.id;
            }

            const payload = {
                sender_id: userInfo.id,
                content: newMessage,
                message_type: activeTab,
                organization_id: userInfo.organization_id,
                department_id: activeTab === 'department' ? userInfo.department_id : null,
                receiver_id: receiverIdNum
            };

            await api.post('/messages/', payload);
            setNewMessage('');
            fetchMessages();
        } catch (error) {
            console.error("Error sending message:", error.response?.data || error);
        }
    };

    // Filter messages based on selected contact and tab
    const getFilteredMessages = () => {
        if (selectedContact) {
            if (activeTab === 'personal') {
                // Personal: show 1-on-1 conversation
                return messages.filter(msg =>
                    (msg.sender_id === selectedContact.id && msg.receiver_id === userInfo.id) ||
                    (msg.sender_id === userInfo.id && msg.receiver_id === selectedContact.id)
                );
            } else {
                // Department/Community: show messages from selected contact
                return messages.filter(msg => msg.sender_id === selectedContact.id);
            }
        }
        return messages;
    };

    // Filter contacts based on tab and search query
    const getFilteredContacts = () => {
        let filteredByTab = contacts;

        // Filter by tab type
        if (activeTab === 'department') {
            // Department tab: Show only department head (HOD)
            filteredByTab = contacts.filter(contact => contact.is_department_head === true);
        }
        // Personal and Community tabs show all contacts

        // Apply search filter
        if (!searchQuery) return filteredByTab;
        return filteredByTab.filter(contact =>
            contact.full_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            contact.username?.toLowerCase().includes(searchQuery.toLowerCase())
        );
    };

    // Group contacts by department for Community tab
    const getGroupedContacts = () => {
        const grouped = {};
        filteredContacts.forEach(contact => {
            const deptName = contact.department_name || 'No Department';
            if (!grouped[deptName]) {
                grouped[deptName] = [];
            }
            grouped[deptName].push(contact);
        });
        return grouped;
    };

    const filteredMessages = getFilteredMessages();
    const filteredContacts = getFilteredContacts();

    return (
        <div className="messaging-container slide-up">
            <header className="page-header custom-messaging-header">
                <div className="header-title-section">
                    <h2><MessageSquare size={28} /> Message System</h2>
                </div>
                <div className="tab-group-modern">
                    <button
                        className={`tab-btn-modern ${activeTab === 'personal' ? 'active' : ''}`}
                        onClick={() => setActiveTab('personal')}
                    >
                        <User size={16} /> Personal
                    </button>
                    <button
                        className={`tab-btn-modern ${activeTab === 'department' ? 'active' : ''}`}
                        onClick={() => setActiveTab('department')}
                    >
                        <Building size={16} /> Department
                    </button>
                    <button
                        className={`tab-btn-modern ${activeTab === 'community' ? 'active' : ''}`}
                        onClick={() => setActiveTab('community')}
                    >
                        <Users size={16} /> Community
                    </button>
                </div>
            </header>

            <div className="messaging-layout card">
                {/* Contact List Sidebar - Now shown in ALL tabs */}
                <div className="contacts-sidebar">
                    <div className="contacts-header">
                        <h3>{activeTab === 'personal' ? 'Contacts' : activeTab === 'department' ? 'Department Members' : 'Community Members'}</h3>
                        <div className="search-box">
                            <Search size={16} />
                            <input
                                type="text"
                                placeholder="Search..."
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                            />
                        </div>
                    </div>
                    <div className="contacts-list">
                        {activeTab === 'community' ? (
                            // Community tab: Show grouped by department
                            Object.keys(getGroupedContacts()).length > 0 ? (
                                Object.entries(getGroupedContacts()).map(([deptName, deptContacts]) => (
                                    <div key={deptName} className="department-group">
                                        <div className="department-group-header">{deptName}</div>
                                        {deptContacts.map(contact => (
                                            <div
                                                key={contact.id}
                                                className={`contact-item ${selectedContact?.id === contact.id ? 'active' : ''}`}
                                                onClick={() => setSelectedContact(contact)}
                                            >
                                                <div className="contact-avatar">
                                                    {(contact.full_name || contact.username).charAt(0).toUpperCase()}
                                                </div>
                                                <div className="contact-info">
                                                    <div className="contact-name">{contact.full_name || contact.username}</div>
                                                    {contact.department_name && (
                                                        <div className="contact-dept">{contact.department_name}</div>
                                                    )}
                                                    <div className="contact-role">{contact.role}</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ))
                            ) : (
                                <div className="no-contacts">No contacts found</div>
                            )
                        ) : (
                            // Personal and Department tabs: Show flat list
                            filteredContacts.length > 0 ? (
                                filteredContacts.map(contact => (
                                    <div
                                        key={contact.id}
                                        className={`contact-item ${selectedContact?.id === contact.id ? 'active' : ''}`}
                                        onClick={() => setSelectedContact(contact)}
                                    >
                                        <div className="contact-avatar">
                                            {(contact.full_name || contact.username).charAt(0).toUpperCase()}
                                        </div>
                                        <div className="contact-info">
                                            <div className="contact-name">{contact.full_name || contact.username}</div>
                                            {contact.department_name && (
                                                <div className="contact-dept">{contact.department_name}</div>
                                            )}
                                            <div className="contact-role">{contact.role}</div>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="no-contacts">
                                    {activeTab === 'department' ? 'No department head found' : 'No contacts found'}
                                </div>
                            )
                        )}
                    </div>
                </div>

                {/* Chat Panel */}
                <div className="chat-panel">
                    {!selectedContact ? (
                        <div className="no-chat-selected">
                            <MessageSquare size={64} className="text-muted" />
                            <h3>Select a contact to view messages</h3>
                            <p className="text-muted">
                                {activeTab === 'personal' ? 'Choose someone to start a private conversation' :
                                    activeTab === 'department' ? 'Select a member to see their department messages' :
                                        'Select a member to see their community messages'}
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Chat Header */}
                            {selectedContact && (
                                <div className="chat-header">
                                    <div className="chat-contact-avatar">
                                        {(selectedContact.full_name || selectedContact.username).charAt(0).toUpperCase()}
                                    </div>
                                    <div className="chat-contact-info">
                                        <h4>{selectedContact.full_name || selectedContact.username}</h4>
                                        <span className="chat-contact-role">
                                            {activeTab === 'personal' ? `Private Chat • ${selectedContact.role}` :
                                                activeTab === 'department' ? `Department Messages • ${selectedContact.role}` :
                                                    `Community Messages • ${selectedContact.role}`}
                                        </span>
                                    </div>
                                </div>
                            )}

                            {/* Messages Window */}
                            <div className="messages-window">
                                {filteredMessages.length > 0 ? (
                                    <div className="messages-list-styled">
                                        {filteredMessages.map(msg => (
                                            <div key={msg.id} className={`message-bubble-wrapper ${msg.sender_id === userInfo.id ? 'sent' : 'received'}`}>
                                                <div className="message-bubble">
                                                    <div className="msg-content">{msg.content}</div>
                                                    <div className="msg-meta">
                                                        <span
                                                            className={`msg-author ${msg.sender_id !== userInfo.id && activeTab !== 'personal' ? 'clickable' : ''}`}
                                                            onClick={() => msg.sender_id !== userInfo.id && activeTab !== 'personal' && handleSenderClick(msg.sender_id)}
                                                            title={msg.sender_id !== userInfo.id && activeTab !== 'personal' ? 'Click to open personal chat' : ''}
                                                        >
                                                            {msg.sender_id === userInfo.id ? 'You' : (msg.sender_name || `User #${msg.sender_id}`)}
                                                        </span>
                                                        <span className="msg-time">{formatMessageTime(msg.timestamp)}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                        <div ref={messagesEndRef} />
                                    </div>
                                ) : (
                                    <div className="empty-messages">
                                        <MessageSquare size={48} className="text-muted" />
                                        <p>No messages yet.</p>
                                        <span className="text-muted">Start the conversation below</span>
                                    </div>
                                )}
                            </div>

                            {/* Message Input */}
                            <div className="message-input-area border-top">
                                <form onSubmit={handleSendMessage} className="message-compose-form">
                                    <input
                                        type="text"
                                        placeholder={
                                            activeTab === 'personal'
                                                ? `Message ${selectedContact?.full_name || selectedContact?.username || ''}...`
                                                : `Post to ${activeTab} channel...`
                                        }
                                        className="form-input message-input"
                                        value={newMessage}
                                        onChange={(e) => setNewMessage(e.target.value)}
                                        required
                                    />
                                    <button type="submit" className="btn-primary send-btn">
                                        <Send size={18} />
                                        <span>Send</span>
                                    </button>
                                </form>
                            </div>
                        </>
                    )}
                </div>
            </div>

            <style>{`
                .custom-messaging-header {
                    display: flex;
                    justify-content: flex-start !important;
                    align-items: center;
                    gap: 20px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid var(--border-color);
                    margin-bottom: 20px;
                }
                .messaging-layout {
                    display: flex;
                    height: calc(100vh - 250px);
                    overflow: hidden;
                    background: var(--bg-card);
                    border-radius: 12px;
                }
                
                /* Contact Sidebar */
                .contacts-sidebar {
                    width: 320px;
                    border-right: 1px solid var(--border-color);
                    display: flex;
                    flex-direction: column;
                    background: var(--bg-secondary);
                }
                .contacts-header {
                    padding: 20px;
                    border-bottom: 1px solid var(--border-color);
                }
                .contacts-header h3 {
                    margin: 0 0 12px 0;
                    font-size: 1.1rem;
                    color: var(--text-primary);
                }
                .search-box {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    background: var(--bg-card);
                    padding: 8px 12px;
                    border-radius: 8px;
                    border: 1px solid var(--border-color);
                }
                .search-box input {
                    border: none;
                    background: transparent;
                    outline: none;
                    flex: 1;
                    color: var(--text-primary);
                    font-size: 0.9rem;
                }
                .contacts-list {
                    flex: 1;
                    overflow-y: auto;
                }
                .contact-item {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 12px 20px;
                    cursor: pointer;
                    transition: all 0.2s;
                    border-bottom: 1px solid rgba(255,255,255,0.05);
                }
                .contact-item:hover {
                    background: rgba(255,255,255,0.05);
                }
                .contact-item.active {
                    background: var(--color-primary);
                    color: white;
                }
                .contact-avatar {
                    width: 40px;
                    height: 40px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, var(--color-primary), var(--color-primary-hover));
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: 600;
                    font-size: 1.1rem;
                    color: white;
                }
                .contact-item.active .contact-avatar {
                    background: white;
                    color: var(--color-primary);
                }
                .contact-info {
                    flex: 1;
                    min-width: 0;
                }
                .contact-name {
                    font-weight: 500;
                    font-size: 0.95rem;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .contact-role {
                    font-size: 0.8rem;
                    opacity: 0.7;
                    margin-top: 2px;
                }
                .contact-dept {
                    font-size: 0.75rem;
                    color: var(--color-primary);
                    font-weight: 500;
                    margin-top: 2px;
                    opacity: 0.9;
                }
                .no-contacts {
                    padding: 40px 20px;
                    text-align: center;
                    color: var(--text-secondary);
                }
                .department-group {
                    margin-bottom: 8px;
                }
                .department-group-header {
                    padding: 8px 20px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    text-transform: uppercase;
                    color: var(--color-primary);
                    background: rgba(59, 130, 246, 0.1);
                    letter-spacing: 0.5px;
                    position: sticky;
                    top: 0;
                    z-index: 1;
                }
                
                /* Chat Panel */
                .chat-panel {
                    flex: 1;
                    display: flex;
                    flex-direction: column;
                    background: var(--bg-card);
                }
                .no-chat-selected {
                    flex: 1;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    gap: 16px;
                    color: var(--text-secondary);
                }
                .no-chat-selected h3 {
                    margin: 0;
                    color: var(--text-primary);
                }
                .chat-header {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding: 16px 24px;
                    border-bottom: 1px solid var(--border-color);
                    background: var(--bg-secondary);
                }
                .chat-contact-avatar {
                    width: 44px;
                    height: 44px;
                    border-radius: 50%;
                    background: linear-gradient(135deg, var(--color-primary), var(--color-primary-hover));
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: 600;
                    font-size: 1.2rem;
                    color: white;
                }
                .chat-contact-info h4 {
                    margin: 0;
                    font-size: 1rem;
                    color: var(--text-primary);
                }
                .chat-contact-role {
                    font-size: 0.85rem;
                    color: var(--text-secondary);
                }
                .messages-window {
                    flex: 1;
                    overflow-y: auto;
                    padding: 24px;
                    background: rgba(15, 23, 42, 0.2);
                }
                .messages-list-styled {
                    display: flex;
                    flex-direction: column;
                    gap: 16px;
                }
                .message-bubble-wrapper {
                    display: flex;
                    width: 100%;
                }
                .message-bubble-wrapper.sent {
                    justify-content: flex-end;
                }
                .message-bubble {
                    max-width: 70%;
                    padding: 12px 18px;
                    border-radius: 18px;
                    position: relative;
                    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
                }
                .sent .message-bubble {
                    background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-hover) 100%);
                    color: white;
                    border-bottom-right-radius: 4px;
                }
                .received .message-bubble {
                    background: var(--bg-secondary);
                    border: 1px solid var(--border-color);
                    color: var(--text-primary);
                    border-bottom-left-radius: 4px;
                }
                .msg-meta {
                    display: flex;
                    justify-content: space-between;
                    font-size: 0.7rem;
                    margin-top: 6px;
                    opacity: 0.8;
                    gap: 12px;
                }
                .msg-author.clickable {
                    cursor: pointer;
                    text-decoration: underline;
                    font-weight: 600;
                    transition: all 0.2s ease;
                }
                .msg-author.clickable:hover {
                    opacity: 1;
                    color: var(--color-primary);
                    transform: scale(1.05);
                }
                .empty-messages {
                    height: 100%;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    gap: 12px;
                }
                .message-input-area {
                    padding: 20px;
                    background: var(--bg-card);
                }
                .message-compose-form {
                    display: flex;
                    gap: 12px;
                    align-items: center;
                }
                .message-input {
                    flex: 1;
                    height: 44px;
                    padding: 0 16px;
                }
                .tab-group-modern {
                    display: flex;
                    background: var(--bg-secondary);
                    padding: 4px;
                    border-radius: 12px;
                    border: 1px solid var(--border-color);
                }
                .tab-btn-modern {
                    padding: 8px 18px;
                    border-radius: 10px;
                    border: none;
                    background: transparent;
                    color: var(--text-secondary);
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    font-size: 0.875rem;
                    font-weight: 500;
                    transition: all 0.2s;
                }
                .tab-btn-modern:hover {
                    color: var(--text-primary);
                    background: rgba(255,255,255,0.05);
                }
                .tab-btn-modern.active {
                    background: var(--color-primary);
                    color: white;
                    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
                }
                .border-top {
                    border-top: 1px solid var(--border-color);
                }
                .send-btn {
                    padding: 10px 24px;
                }
            `}</style>
        </div>
    );
};

export default Messaging;
