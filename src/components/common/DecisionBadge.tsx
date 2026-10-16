import React from 'react';
import { DecisionType } from '../../types/agentguard';
import { CheckCircle2, ShieldAlert, Clock, EyeOff } from 'lucide-react';

interface DecisionBadgeProps {
  decision: DecisionType;
  size?: 'sm' | 'md' | 'lg';
}

export const DecisionBadge: React.FC<DecisionBadgeProps> = ({ decision, size = 'md' }) => {
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3 py-1.5 gap-2',
  };

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  };

  switch (decision) {
    case 'ALLOW':
      return (
        <span
          className={`inline-flex items-center font-semibold rounded border border-emerald-500/30 bg-emerald-950/40 text-emerald-300 ${sizeClasses[size]}`}
          title="Permitted tool execution"
        >
          <CheckCircle2 size={iconSizes[size]} className="text-emerald-400 shrink-0" />
          <span>ALLOW</span>
        </span>
      );

    case 'BLOCK':
      return (
        <span
          className={`inline-flex items-center font-semibold rounded border border-rose-500/40 bg-rose-950/50 text-rose-300 ${sizeClasses[size]}`}
          title="Blocked malicious or unauthorized tool call"
        >
          <ShieldAlert size={iconSizes[size]} className="text-rose-400 shrink-0" />
          <span>BLOCK</span>
        </span>
      );

    case 'REQUIRE_APPROVAL':
      return (
        <span
          className={`inline-flex items-center font-semibold rounded border border-amber-500/40 bg-amber-950/40 text-amber-300 ${sizeClasses[size]}`}
          title="Quarantined pending human-in-the-loop review"
        >
          <Clock size={iconSizes[size]} className="text-amber-400 shrink-0" />
          <span>REQUIRE_APPROVAL</span>
        </span>
      );

    case 'REDACT':
      return (
        <span
          className={`inline-flex items-center font-semibold rounded border border-purple-500/40 bg-purple-950/40 text-purple-300 ${sizeClasses[size]}`}
          title="Sensitive data or credentials sanitized"
        >
          <EyeOff size={iconSizes[size]} className="text-purple-400 shrink-0" />
          <span>REDACT</span>
        </span>
      );

    default:
      return (
        <span className={`inline-flex items-center rounded border border-slate-700 bg-slate-800 text-slate-300 ${sizeClasses[size]}`}>
          {decision}
        </span>
      );
  }
};
