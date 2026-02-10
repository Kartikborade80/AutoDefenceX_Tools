import React, { useState, useEffect } from 'react';
import api from '../api';
import { CheckSquare, Plus, Clock, AlertCircle, CheckCircle2, Trash2 } from 'lucide-react';

const Tasks = () => {
    const [tasks, setTasks] = useState([]);
    const [loading, setLoading] = useState(true);
    const userInfo = JSON.parse(localStorage.getItem('user_info') || '{}');
    const [newTask, setNewTask] = useState({ title: '', description: '', assigned_to_id: '', priority: 'medium' });
    const [departments, setDepartments] = useState([]);
    const [usersInDept, setUsersInDept] = useState([]);
    const [selectedDeptId, setSelectedDeptId] = useState('');
    const isDH = userInfo.is_department_head;
    const isAdmin = userInfo.role === 'admin';

    useEffect(() => {
        const fetchTasks = async () => {
            try {
                if (isDH) {
                    // For HODs, fetch BOTH tasks they created and tasks assigned TO them
                    const [createdRes, assignedRes] = await Promise.all([
                        api.get(`/tasks/assigned-by/${userInfo.id}`),
                        api.get(`/tasks/assigned-to/${userInfo.id}`)
                    ]);

                    // Merge and label
                    const created = createdRes.data.map(t => ({ ...t, _type: 'created' }));
                    const assigned = assignedRes.data.map(t => ({ ...t, _type: 'assigned' }));

                    // Remove duplicates if any (same task could be self-assigned)
                    const merged = [...created];
                    assigned.forEach(a => {
                        if (!merged.find(m => m.id === a.id)) {
                            merged.push(a);
                        } else {
                            // If it exists in both, it's self-assigned
                            const idx = merged.findIndex(m => m.id === a.id);
                            merged[idx]._is_self = true;
                        }
                    });

                    setTasks(merged.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
                } else {
                    const response = await api.get(`/tasks/assigned-to/${userInfo.id}`);
                    setTasks(response.data);
                }
            } catch (error) {
                console.error("Error fetching tasks:", error);
            } finally {
                setLoading(false);
            }
        };

        const fetchDepartments = async () => {
            try {
                const response = await api.get('/departments/');
                setDepartments(response.data);
            } catch (error) {
                console.error("Error fetching departments:", error);
            }
        };

        fetchTasks();
        if (isDH) fetchDepartments();
    }, [userInfo.id, isDH]);

    useEffect(() => {
        if (selectedDeptId) {
            const fetchUsers = async () => {
                try {
                    const response = await api.get(`/users/active?department_id=${selectedDeptId}`);
                    setUsersInDept(response.data);
                } catch (error) {
                    console.error("Error fetching users:", error);
                }
            };
            fetchUsers();
        } else {
            setUsersInDept([]);
        }
    }, [selectedDeptId]);

    const handleCreateTask = async (e) => {
        e.preventDefault();
        try {
            const response = await api.post('/tasks/', { ...newTask, assigned_by_id: userInfo.id });
            setTasks([...tasks, response.data]);
            setNewTask({ title: '', description: '', assigned_to_id: '', priority: 'medium' });
            setSelectedDeptId('');
        } catch (error) {
            console.error("Error creating task:", error);
        }
    };

    const handleUpdateStatus = async (taskId, newStatus) => {
        try {
            const response = await api.put(`/tasks/${taskId}`, { status: newStatus });
            setTasks(tasks.map(t => t.id === taskId ? response.data : t));
        } catch (error) {
            console.error("Error updating task:", error);
        }
    };

    const handleDeleteTask = async (taskId) => {
        if (!window.confirm("Are you sure you want to delete this task?")) return;
        try {
            await api.delete(`/tasks/${taskId}`);
            setTasks(tasks.filter(t => t.id !== taskId));
        } catch (error) {
            console.error("Error deleting task:", error);
            alert("Failed to delete task. You might not have permission.");
        }
    };

    return (
        <div className="tasks-container slide-up">
            <header className="page-header">
                <div className="header-title-area">
                    <h2><CheckSquare size={28} /> Task Management</h2>
                    <p className="text-muted">{isDH ? "Assign and monitor tasks for your department." : "View and update your assigned tasks."}</p>
                </div>
            </header>

            <div className="tasks-grid">
                {isDH && (
                    <div className="create-task-column">
                        <section className="create-task-section card">
                            <h3 className="section-title"><Plus size={20} /> Assign New Task</h3>
                            <form onSubmit={handleCreateTask} className="task-form-styled">
                                <div className="form-group">
                                    <label>Task Title</label>
                                    <input type="text" className="form-input" placeholder="Enter task title..." value={newTask.title} onChange={e => setNewTask({ ...newTask, title: e.target.value })} required />
                                </div>
                                <div className="form-group">
                                    <label>Detailed Description</label>
                                    <textarea className="form-input" placeholder="Explain the work..." value={newTask.description} onChange={e => setNewTask({ ...newTask, description: e.target.value })} />
                                </div>
                                <div className="form-group">
                                    <label>Department</label>
                                    <select
                                        className="form-input"
                                        value={selectedDeptId}
                                        onChange={e => setSelectedDeptId(e.target.value)}
                                        required
                                    >
                                        <option value="">-- Select Department --</option>
                                        {departments.map(dept => (
                                            <option key={dept.id} value={dept.id}>{dept.name}</option>
                                        ))}
                                    </select>
                                </div>

                                <div className="form-row">
                                    <div className="form-group flex-1">
                                        <label>Assign to User</label>
                                        <select
                                            className="form-input"
                                            value={newTask.assigned_to_id}
                                            onChange={e => setNewTask({ ...newTask, assigned_to_id: e.target.value })}
                                            required
                                            disabled={!selectedDeptId}
                                        >
                                            <option value="">-- Select Member --</option>
                                            {usersInDept.map(user => (
                                                <option key={user.id} value={user.id}>{user.full_name || user.username}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="form-group flex-1">
                                        <label>Priority</label>
                                        <select className="form-input" value={newTask.priority} onChange={e => setNewTask({ ...newTask, priority: e.target.value })}>
                                            <option value="low">Low</option>
                                            <option value="medium">Medium</option>
                                            <option value="high">High</option>
                                        </select>
                                    </div>
                                </div>
                                <button type="submit" className="btn-primary w-full mt-md">
                                    <Plus size={18} /> Assign Task
                                </button>
                            </form>
                        </section>
                    </div>
                )}

                <div className={`tasks-list-column ${!isDH ? 'full-width' : ''}`}>
                    {loading ? (
                        <div className="loading-state card">
                            <div className="loader"></div>
                            <p>Fetching latest tasks...</p>
                        </div>
                    ) : (
                        <div className="tasks-scroll-area">
                            {tasks.length > 0 ? (
                                <div className="tasks-masonry">
                                    {tasks.map(task => (
                                        <div key={task.id} className={`task-card-modern card priority-${task.priority} ${task.status}`}>
                                            <div className="task-card-header">
                                                <h4 className="task-title">{task.title}</h4>
                                                <span className={`status-pill ${task.status}`}>{task.status.replace('_', ' ')}</span>
                                            </div>
                                            <p className="task-desc">{task.description}</p>
                                            <div className="task-card-footer">
                                                <div className="task-tags">
                                                    <span className={`priority-badge ${task.priority}`}>
                                                        {task.priority === 'high' && <AlertCircle size={12} />}
                                                        {task.priority}
                                                    </span>
                                                </div>
                                                <div className="task-meta-info">
                                                    <Clock size={12} />
                                                    <span>{new Date(task.created_at).toLocaleDateString()}</span>
                                                </div>
                                            </div>

                                            {/* Action Buttons */}
                                            <div className="task-actions-row">
                                                {/* Complete Button */}
                                                {(task.assigned_to_id === userInfo.id || isDH) && task.status !== 'completed' && (
                                                    <button onClick={() => handleUpdateStatus(task.id, 'completed')} className="btn-primary btn-sm flex-1 success-alt">
                                                        <CheckCircle2 size={14} /> Complete Task
                                                    </button>
                                                )}

                                                {/* Delete Button - Only for Creator or Admin */}
                                                {(isAdmin || task.assigned_by_id === userInfo.id) && (
                                                    <button onClick={() => handleDeleteTask(task.id)} className="btn-delete btn-sm" title="Delete Task">
                                                        <Trash2 size={14} />
                                                    </button>
                                                )}
                                            </div>

                                            {isDH && task.assigned_to_id !== userInfo.id && (
                                                <div className="task-meta-assigned-to" style={{ marginTop: '8px' }}>
                                                    <span className="text-xs text-muted">Assigned to ID: #{task.assigned_to_id}</span>
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="empty-tasks card">
                                    <CheckSquare size={64} className="text-muted" />
                                    <h3>No Tasks Found</h3>
                                    <p className="text-muted">Tasks assigned to you will appear here.</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            <style>{`
                .tasks-grid {
                    display: grid;
                    grid-template-columns: ${isDH ? '350px 1fr' : '1fr'};
                    gap: 30px;
                    align-items: start;
                }
                .section-title {
                    font-size: 1.1rem;
                    margin-bottom: 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    color: var(--brand-blue);
                }
                .task-form-styled {
                    background: rgba(255, 255, 255, 0.03);
                    padding: 24px;
                    border-radius: 16px;
                    border: 1px solid var(--border-glass);
                }
                .form-group {
                    margin-bottom: 16px;
                }
                .form-group label {
                    display: block;
                    font-size: 0.85rem;
                    color: var(--text-secondary);
                    margin-bottom: 8px;
                    font-weight: 500;
                }
                .form-row {
                    display: flex;
                    gap: 12px;
                }
                .flex-1 { flex: 1; }
                .w-full { width: 100%; }
                
                .tasks-scroll-area {
                    max-height: calc(100vh - 200px);
                    overflow-y: auto;
                    padding-right: 8px;
                }

                .tasks-masonry {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
                    gap: 20px;
                }
                
                .task-card-modern {
                    background: var(--bg-card);
                    border: 1px solid var(--border-glass);
                    border-radius: 12px;
                    padding: 20px;
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                    transition: transform 0.2s, box-shadow 0.2s;
                    position: relative;
                    overflow: hidden;
                }
                .task-card-modern:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
                    border-color: var(--color-primary);
                }
                
                .task-card-modern::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 4px;
                    height: 100%;
                }
                .task-card-modern.priority-high::before { background: var(--color-danger); }
                .task-card-modern.priority-medium::before { background: var(--color-warning); }
                .task-card-modern.priority-low::before { background: var(--color-success); }
                
                .task-card-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                }
                .task-title {
                    font-size: 1.1rem;
                    font-weight: 600;
                    margin: 0;
                    color: var(--text-primary);
                }
                .status-pill {
                    font-size: 0.7rem;
                    text-transform: uppercase;
                    font-weight: 700;
                    padding: 4px 10px;
                    border-radius: 6px;
                }
                .status-pill.pending { background: rgba(245, 158, 11, 0.1); color: #f59e0b; }
                .status-pill.in_progress { background: rgba(59, 130, 246, 0.1); color: #3b82f6; }
                .status-pill.completed { background: rgba(16, 185, 129, 0.1); color: #10b981; }
                
                .task-desc {
                    font-size: 0.95rem;
                    color: var(--text-secondary);
                    line-height: 1.5;
                    margin: 0;
                    flex-grow: 1;
                }
                .task-card-footer {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding-top: 15px;
                    border-top: 1px solid rgba(255,255,255,0.05);
                    margin-top: auto;
                }
                .priority-badge {
                    font-size: 0.75rem;
                    text-transform: capitalize;
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    padding: 4px 12px;
                    border-radius: 20px;
                    background: rgba(255, 255, 255, 0.05);
                    font-weight: 500;
                }
                .priority-badge.high { color: var(--color-danger); background: rgba(239, 68, 68, 0.1); }
                .priority-badge.medium { color: var(--color-warning); background: rgba(245, 158, 11, 0.1); }
                .priority-badge.low { color: var(--color-success); background: rgba(16, 185, 129, 0.1); }
                
                .task-meta-info {
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    font-size: 0.8rem;
                    color: var(--text-muted);
                }
                .task-actions-row {
                    display: flex;
                    gap: 12px;
                    margin-top: 15px;
                }
                .btn-sm { padding: 8px 16px; font-size: 0.85rem; border-radius: 8px;}
                .success-alt { background: var(--color-success); border: none; }
                .success-alt:hover { background: #059669; }
                
                .empty-tasks {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 60px;
                    text-align: center;
                    gap: 16px;
                    background: rgba(255, 255, 255, 0.02);
                    border-radius: 16px;
                    border: 1px dashed var(--border-color);
                }
            `}</style>
        </div>
    );
};

export default Tasks;
