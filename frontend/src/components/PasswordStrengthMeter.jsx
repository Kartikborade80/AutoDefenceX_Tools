import React, { useState, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react';

const PasswordStrengthMeter = ({ password }) => {
    const [strength, setStrength] = useState(0);
    const [feedback, setFeedback] = useState([]);

    const evaluatePassword = (pwd) => {
        let score = 0;
        let tips = [];

        if (!pwd) return { score: 0, tips: [] };

        if (pwd.length >= 8) {
            score += 1;
        } else {
            tips.push("At least 8 characters");
        }

        if (/[A-Z]/.test(pwd)) {
            score += 1;
        } else {
            tips.push("Uppercase letters");
        }

        if (/[a-z]/.test(pwd)) {
            score += 1;
        } else {
            tips.push("Lowercase letters");
        }

        if (/\d/.test(pwd)) {
            score += 1;
        } else {
            tips.push("Digits (0-9)");
        }

        if (/[!@#$%^&*(),.?":{}|<>]/.test(pwd)) {
            score += 1;
        } else {
            tips.push("Special characters");
        }

        return { score, tips };
    };

    useEffect(() => {
        const { score, tips } = evaluatePassword(password);
        setStrength(score);
        setFeedback(tips);
    }, [password]);

    const getStrengthColor = () => {
        if (strength <= 1) return 'bg-red-500';
        if (strength <= 2) return 'bg-orange-500';
        if (strength <= 3) return 'bg-yellow-500';
        if (strength <= 4) return 'bg-blue-500';
        return 'bg-green-500';
    };

    const getStrengthLabel = () => {
        if (strength <= 1) return 'Very Weak';
        if (strength <= 2) return 'Weak';
        if (strength <= 3) return 'Fair';
        if (strength <= 4) return 'Strong';
        return 'Very Strong';
    };

    const getStrengthIcon = () => {
        if (strength <= 2) return <ShieldOff className="w-4 h-4 text-red-500" />;
        if (strength <= 4) return <ShieldAlert className="w-4 h-4 text-yellow-500" />;
        return <ShieldCheck className="w-4 h-4 text-green-500" />;
    };

    if (!password) return null;

    return (
        <div className="mt-3 space-y-2">
            <div className="flex items-center justify-between text-xs font-medium">
                <div className="flex items-center gap-1.5 grayscale opacity-70">
                    {getStrengthIcon()}
                    <span className="text-white/70">Strength: </span>
                    <span className={`font-bold ${strength >= 5 ? 'text-green-400' : 'text-white/90'}`}>
                        {getStrengthLabel()}
                    </span>
                </div>
                <span className="text-white/40">{strength}/5</span>
            </div>

            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden flex gap-1">
                {[1, 2, 3, 4, 5].map((level) => (
                    <div
                        key={level}
                        className={`h-full flex-1 transition-all duration-300 rounded-full ${level <= strength ? getStrengthColor() : 'bg-transparent'
                            }`}
                    />
                ))}
            </div>

            {feedback.length > 0 && (
                <div className="text-[10px] text-white/40 leading-tight">
                    Required: {feedback.join(', ')}
                </div>
            )}
        </div>
    );
};

export default PasswordStrengthMeter;
