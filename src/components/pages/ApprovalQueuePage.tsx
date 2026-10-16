import React, { useState } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { CodeBlock } from '../common/CodeBlock';
import { ApprovalActionModal } from '../modals/ApprovalActionModal';
import { ApprovalRequest } from '../../types/agentguard';
import {
  CheckSquare,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Shield,
  Info,
  UserCheck,
  Terminal,
} from 'lucide-react';

export const ApprovalQueuePage: React.FC = () => {
  const { approvals, isBackendConnected, dbState, operatingState } = useSecurity();

  const [selectedApproval, setSelectedApproval] = useState<ApprovalRequest | null>(null);
  const [modalAction, setModalAction] = useState<'APPROVED' | 'REJECTED' | null>(null);
  const [filterTab, setFilterTab] = useState<'PENDING' | 'RESOLVED'>('PENDING');

  const pendingApprovals = approvals.filter((a) => a.status === 'PENDING');
  const resolvedApprovals = approvals.filter((a) => a.status !== 'PENDING');

  const displayedList = filterTab === 'PENDING' ? pendingApprovals : resolvedApprovals;

  const handleOpenAction = (approval: ApprovalRequest, action: 'APPROVED' | 'REJECTED') => {
    setSelectedApproval(approval);
    setModalAction(action);
  };

  const isLiveBackend = isBackendConnected && operatingState === 'LIVE';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <CheckSquare size={15} className="text-amber-400" />
            Human-in-the-Loop (HITL) Authorization Queue
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Quarantined tool operations requiring explicit analyst authorization before execution resumption
          </p>
        </div>

        {/* Tab segmented filter */}
        <div className="flex items-center p-0.5 bg-slate-900 border border-slate-800 rounded text-xs font-mono">
          <button
            onClick={() => setFilterTab('PENDING')}
            className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
              filterTab === 'PENDING'
                ? 'bg-amber-950/60 text-amber-300 border border-amber-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock size={11} />
            <span>Pending ({pendingApprovals.length})</span>
          </button>
          <button
            onClick={() => setFilterTab('RESOLVED')}
            className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
              filterTab === 'RESOLVED'
                ? 'bg-slate-800 text-slate-200 border border-slate-700 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <CheckCircle2 size={11} />
            <span>Resolved History ({resolvedApprovals.length})</span>
          </button>
        </div>
      </div>

      {/* Protocol Transparency Strip */}
      <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] flex items-center justify-between gap-3 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <Info size={13} className="text-cyan-400 shrink-0" />
          <span>
            {isLiveBackend
              ? 'Live Execution Engine Active: Authorizing sends an unblock signal to /api/approvals/:id/decision and logs an immutable audit entry.'
              : 'Local / Demo Mode: Approving or rejecting updates the SOC workflow state and records the decision to the audit trail.'}
          </span>
        </div>
        <span className="text-slate-300 font-semibold shrink-0">
          HITL Gate: Active
        </span>
      </div>

      {/* Approvals Table / Dense Cards */}
      <div className="space-y-3">
        {displayedList.length === 0 ? (
          <div className="p-12 text-center rounded-lg border border-dashed border-slate-800 bg-[#0d1424] text-xs text-slate-400 space-y-1">
            <UserCheck size={24} className="mx-auto text-slate-500 mb-2" />
            <p className="font-medium text-slate-300 font-mono">
              {filterTab === 'PENDING' ? 'Zero pending requests in authorization queue' : 'No resolved approval records found'}
            </p>
            <p className="text-[11px] text-slate-400">
              {filterTab === 'PENDING' ? 'All quarantined MCP tool calls have been evaluated.' : ''}
            </p>
          </div>
        ) : (
          displayedList.map((approval) => (
            <div
              key={approval.id}
              className="p-4 rounded-lg border border-slate-800/90 bg-[#0d1424] hover:border-slate-700 transition-colors space-y-3"
            >
              {/* Row 1: Identification & Metadata */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5 flex-wrap font-mono text-xs">
                    <span className="text-cyan-400 font-bold">
                      {approval.id}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-200 font-semibold">
                      Tool: {approval.serverName}/{approval.toolName}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400">Agent:</span>
                    <span className="text-slate-100 font-semibold">
                      {approval.agentName}
                    </span>
                  </div>
                  <div className="text-[11px] text-amber-300 flex items-center gap-1.5 font-sans">
                    <AlertTriangle size={12} className="text-amber-400 shrink-0" />
                    <span>{approval.policyReason}</span>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
                  <RiskScoreBadge score={approval.riskScore} />
                  <span className="text-slate-400 text-[11px]">
                    {new Date(approval.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </div>

              {/* Input Arguments CodeBlock */}
              <div>
                <span className="text-[11px] font-medium text-slate-400 block mb-1 font-mono">
                  Quarantined Input Arguments:
                </span>
                <CodeBlock code={approval.inputParams} maxHeight="max-h-32" />
              </div>

              {/* Status & Real Action Buttons */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1">
                {approval.status === 'PENDING' ? (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleOpenAction(approval, 'APPROVED')}
                      className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors flex items-center gap-1.5"
                    >
                      <CheckCircle2 size={13} />
                      <span>Authorize Execution</span>
                    </button>
                    <button
                      onClick={() => handleOpenAction(approval, 'REJECTED')}
                      className="px-3 py-1.5 rounded bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-500/40 text-xs font-semibold transition-colors flex items-center gap-1.5"
                    >
                      <XCircle size={13} />
                      <span>Reject & Block</span>
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5 font-mono text-xs">
                    <span
                      className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
                        approval.status === 'APPROVED'
                          ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                          : 'border-rose-500/40 bg-rose-950/40 text-rose-300'
                      }`}
                    >
                      {approval.status}
                    </span>
                    <span className="text-slate-400 text-[11px]">
                      Reviewed by {approval.reviewer || 'Security Analyst'} at{' '}
                      {approval.reviewedAt && new Date(approval.reviewedAt).toLocaleTimeString()}
                    </span>
                  </div>
                )}

                {approval.analystNotes && (
                  <div className="text-[11px] text-slate-400 italic">
                    Analyst Justification: &ldquo;{approval.analystNotes}&rdquo;
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Action Modal */}
      <ApprovalActionModal
        approval={selectedApproval}
        isOpen={!!selectedApproval && !!modalAction}
        onClose={() => {
          setSelectedApproval(null);
          setModalAction(null);
        }}
        actionType={modalAction}
      />
    </div>
  );
};
