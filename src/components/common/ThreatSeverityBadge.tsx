import React from 'react';
import { ThreatSeverity } from '../../types/agentguard';
import { AlertOctagon, AlertTriangle, Info } from 'lucide-react';

interface ThreatSeverityBadgeProps {
  severity: ThreatSeverity;
}

export const ThreatSeverityBadge: React.FC<ThreatSeverityBadgeProps> = ({ severity }) => {
  switch (severity) {
    case 'CRITICAL':
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded border border-rose-500/50 bg-rose-950/60 text-rose-300">
          <AlertOctagon size={12} className="text-rose-400 shrink-0" />
          <span>CRITICAL</span>
        </span>
      );
    case 'HIGH':
      return (
        <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded border border-orange-500/50 bg-orange-950/50 text-orange-300">
          <AlertTriangle size={12} className="text-orange-400 shrink-0" />
          <span>HIGH</span>
        </span>
      );
    case 'MEDIUM':
      return (
        <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border border-yellow-500/40 bg-yellow-950/40 text-yellow-300">
          <AlertTriangle size={12} className="text-yellow-400 shrink-0" />
          <span>MEDIUM</span>
        </span>
      );
    case 'LOW':
    default:
      return (
        <span className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border border-slate-600 bg-slate-800 text-slate-300">
          <Info size={12} className="text-slate-400 shrink-0" />
          <span>LOW</span>
        </span>
      );
  }
};
