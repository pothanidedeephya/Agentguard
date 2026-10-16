import React from 'react';
import { Modal } from '../common/Modal';
import { ThreatSeverityBadge } from '../common/ThreatSeverityBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { ThreatEvent } from '../../types/agentguard';
import { useSecurity } from '../../context/SecurityContext';
import { ShieldAlert, CheckCircle2, Search, AlertOctagon, Terminal } from 'lucide-react';

interface ThreatDetailModalProps {
  threat: ThreatEvent | null;
  onClose: () => void;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  threat,
  onClose,
}) => {
  const { updateThreatStatus, toolCalls, setSelectedToolCall, setCurrentPage } = useSecurity();

  if (!threat) return null;

  const associatedCall = toolCalls.find((c) => c.id === threat.toolCallId);

  const handleStatusChange = (newStatus: ThreatEvent['status']) => {
    updateThreatStatus(threat.id, newStatus);
    onClose();
  };

  const handleViewCall = () => {
    if (associatedCall) {
      setSelectedToolCall(associatedCall);
      onClose();
      setCurrentPage('tool-calls');
    }
  };

  return (
    <Modal
      isOpen={!!threat}
      onClose={onClose}
      title={`Threat Evidence & Forensics: ${threat.id}`}
      subtitle={`Category: ${threat.category} · Detected at ${new Date(threat.timestamp).toLocaleString()}`}
      maxWidth="max-w-3xl"
    >
      <div className="space-y-4">
        {/* Top Metric Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg border border-slate-800 bg-[#070c16]">
          <div>
            <span className="text-[11px] text-slate-400 block">Severity</span>
            <div className="mt-1">
              <ThreatSeverityBadge severity={threat.severity} />
            </div>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Risk Score</span>
            <div className="mt-1">
              <RiskScoreBadge score={threat.riskScore} />
            </div>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Current Status</span>
            <span className="text-xs font-mono font-semibold text-slate-200 block mt-1">
              {threat.status}
            </span>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Source MCP Tool</span>
            <span className="text-xs font-mono text-cyan-300 block mt-1 truncate">
              {threat.sourceTool}
            </span>
          </div>
        </div>

        {/* Threat Title & Summary */}
        <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-950/20">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-rose-400 shrink-0" />
            <h4 className="text-sm font-semibold text-rose-200">{threat.title}</h4>
          </div>
          <p className="text-xs text-slate-300 mt-2 leading-relaxed">
            Associated Agent: <strong className="text-white">{threat.agentName}</strong> on MCP Server{' '}
            <strong className="text-white">{threat.serverName}</strong>.
          </p>
        </div>

        {/* Transparent Rule-based Evidence */}
        <div className="space-y-2">
          <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
            <Search size={14} className="text-cyan-400" />
            Empirical Evidence & Rule Signature
          </span>
          <div className="p-3.5 rounded-lg border border-slate-800 bg-[#070b12] space-y-2">
            <div>
              <span className="text-[11px] font-mono text-slate-400 block">Rule Signature Triggered:</span>
              <code className="text-xs font-mono text-emerald-400 block mt-0.5">
                {threat.detectionRule}
              </code>
            </div>
            <div className="pt-2 border-t border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block">Extracted Evidence:</span>
              <p className="text-xs font-mono text-slate-200 mt-0.5 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800">
                {threat.evidence}
              </p>
            </div>
          </div>
        </div>

        {/* Recommended Action */}
        <div className="p-3.5 rounded-lg border border-cyan-500/30 bg-cyan-950/20 space-y-1">
          <span className="text-xs font-semibold text-cyan-200 flex items-center gap-1.5">
            <AlertOctagon size={14} className="text-cyan-400" />
            Recommended Analyst Action
          </span>
          <p className="text-xs text-slate-300 leading-relaxed">
            {threat.recommendedAction}
          </p>
        </div>

        {/* Associated Tool Call link */}
        {associatedCall && (
          <div className="flex items-center justify-between p-2.5 rounded-lg border border-slate-800 bg-slate-900/50 text-xs text-slate-400">
            <span>Linked Tool Call: <strong className="text-slate-200 font-mono">{threat.toolCallId}</strong></span>
            <button
              onClick={handleViewCall}
              className="text-cyan-400 hover:text-cyan-200 font-medium underline flex items-center gap-1"
            >
              <Terminal size={12} />
              <span>Inspect Call Forensics</span>
            </button>
          </div>
        )}

        {/* Analyst Status Transitions */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Update Workflow:</span>
            <button
              onClick={() => handleStatusChange('INVESTIGATING')}
              className="px-2.5 py-1 text-xs rounded border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors"
            >
              Set Investigating
            </button>
            <button
              onClick={() => handleStatusChange('MITIGATED')}
              className="px-2.5 py-1 text-xs rounded border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/50 transition-colors"
            >
              Mark Mitigated
            </button>
            <button
              onClick={() => handleStatusChange('FALSE_POSITIVE')}
              className="px-2.5 py-1 text-xs rounded border border-slate-700 bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              False Positive
            </button>
          </div>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
