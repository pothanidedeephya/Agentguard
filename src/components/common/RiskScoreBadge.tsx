import React from 'react';

interface RiskScoreBadgeProps {
  score: number; // 0 - 100
  showLabel?: boolean;
}

export const RiskScoreBadge: React.FC<RiskScoreBadgeProps> = ({ score, showLabel = true }) => {
  let colorStyles = 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30';
  let level = 'LOW';

  if (score >= 90) {
    colorStyles = 'text-rose-400 bg-rose-950/50 border-rose-500/40 font-bold';
    level = 'CRITICAL';
  } else if (score >= 70) {
    colorStyles = 'text-amber-400 bg-amber-950/40 border-amber-500/40 font-semibold';
    level = 'HIGH';
  } else if (score >= 35) {
    colorStyles = 'text-yellow-400 bg-yellow-950/40 border-yellow-500/30 font-medium';
    level = 'MED';
  }

  return (
    <div className="inline-flex items-center gap-1.5">
      <span
        className={`font-mono text-xs px-2 py-0.5 rounded border tabular-nums ${colorStyles}`}
      >
        {score}
      </span>
      {showLabel && (
        <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
          {level}
        </span>
      )}
    </div>
  );
};
