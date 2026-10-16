import React, { useState } from 'react';
import { Modal } from '../common/Modal';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { CodeBlock } from '../common/CodeBlock';
import { ApprovalRequest } from '../../types/agentguard';
import { useSecurity } from '../../context/SecurityContext';
import { CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';

interface ApprovalActionModalProps {
  approval: ApprovalRequest | null;
  isOpen: boolean;
  onClose: () => void;
  actionType: 'APPROVED' | 'REJECTED' | null;
}

export const ApprovalActionModal: React.FC<ApprovalActionModalProps> = ({
  approval,
  isOpen,
  onClose,
  actionType,
}) => {
  const { handleApprovalAction, isBackendConnected } = useSecurity();
  const [analystNotes, setAnalystNotes] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [resultMsg, setResultMsg] = useState<string | null>(null);

  if (!approval || !actionType) return null;

  const isApproving = actionType === 'APPROVED';

  const handleConfirm = async () => {
    setIsSubmitting(true);
    const res = await handleApprovalAction(approval.id, actionType, analystNotes);
    setIsSubmitting(false);
    setResultMsg(res.message);
    setTimeout(() => {
      onClose();
      setResultMsg(null);
      setAnalystNotes('');
    }, 1500);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isApproving ? 'Authorize Tool Execution' : 'Reject & Block Tool Call'}
      subtitle={`Reviewing quarantined request ${approval.id} from ${approval.agentName}`}
      maxWidth="max-w-2xl"
    >
      <div className="space-y-4">
        {/* Real Security Notice */}
        {!isBackendConnected ? (
          <div className="p-3 rounded-lg border border-amber-500/40 bg-amber-950/20 text-xs text-amber-300 flex items-start gap-2.5">
            <Info size={16} className="text-amber-400 mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold">Simulated Demo Workflow: </span>
              The AgentGuard backend is currently running in offline/demo mode. Your approval decision will update local SOC state and audit logs, but tool call execution will <em>not</em> resume on a live production server.
            </div>
          </div>
        ) : (
          <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-950/20 text-xs text-emerald-300 flex items-start gap-2.5">
            <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold">Live Gateway Resumption: </span>
              Confirming this action will transmit an authorization signal to the AgentGuard Gateway on <code>/api/approvals</code> and unblock agent execution.
            </div>
          </div>
        )}

        {resultMsg && (
          <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-xs text-cyan-200">
            {resultMsg}
          </div>
        )}

        {/* Call Summary */}
        <div className="p-3.5 rounded-lg border border-slate-800 bg-[#070c16] space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Target Tool:</span>
            <span className="font-mono text-cyan-300 font-semibold">
              {approval.serverName}/{approval.toolName}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Risk Assessment:</span>
            <RiskScoreBadge score={approval.riskScore} />
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Quarantine Reason:</span>
            <span className="text-slate-200 text-right">{approval.policyReason}</span>
          </div>
        </div>

        {/* Input Parameters Preview */}
        <div>
          <span className="text-xs font-semibold text-slate-300 block mb-1">
            Quarantined Input Arguments
          </span>
          <CodeBlock code={approval.inputParams} maxHeight="max-h-40" />
        </div>

        {/* Analyst Reason Form */}
        <div>
          <label className="text-xs font-medium text-slate-300 block mb-1">
            Analyst Security Rationale / Audit Justification *
          </label>
          <textarea
            value={analystNotes}
            onChange={(e) => setAnalystNotes(e.target.value)}
            rows={2}
            placeholder={
              isApproving
                ? 'e.g., Verified change ticket CHG-401; dry-run executed on staging replica...'
                : 'e.g., Unauthorized DDL operation on production database table...'
            }
            className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500"
          />
        </div>

        {/* Footer Actions */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={isSubmitting}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              isApproving
                ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                : 'bg-rose-600 hover:bg-rose-500 text-white'
            }`}
          >
            {isApproving ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            <span>
              {isSubmitting
                ? 'Transmitting...'
                : isApproving
                ? 'Authorize & Unblock'
                : 'Confirm Block & Reject'}
            </span>
          </button>
        </div>
      </div>
    </Modal>
  );
};
