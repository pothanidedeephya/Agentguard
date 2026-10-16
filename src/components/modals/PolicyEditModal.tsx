import React, { useState, useEffect } from 'react';
import { Modal } from '../common/Modal';
import { PolicyRule, DecisionType } from '../../types/agentguard';
import { useSecurity } from '../../context/SecurityContext';
import { AlertTriangle, CheckCircle2, Shield } from 'lucide-react';

interface PolicyEditModalProps {
  policy: PolicyRule | null;
  isOpen: boolean;
  onClose: () => void;
  isNew?: boolean;
}

export const PolicyEditModal: React.FC<PolicyEditModalProps> = ({
  policy,
  isOpen,
  onClose,
  isNew = false,
}) => {
  const { updatePolicy, addPolicy } = useSecurity();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [ruleType, setRuleType] = useState<PolicyRule['ruleType']>('TOOL_RESTRICTION');
  const [targetTools, setTargetTools] = useState('');
  const [targetServers, setTargetServers] = useState('');
  const [riskThreshold, setRiskThreshold] = useState(80);
  const [action, setAction] = useState<DecisionType>('BLOCK');
  const [enabled, setEnabled] = useState(true);

  // Confirmation & Feedback state
  const [isConfirming, setIsConfirming] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (policy) {
      setName(policy.name);
      setDescription(policy.description);
      setRuleType(policy.ruleType);
      setTargetTools(policy.targetTools.join(', '));
      setTargetServers(policy.targetServers.join(', '));
      setRiskThreshold(policy.riskThreshold);
      setAction(policy.action);
      setEnabled(policy.enabled);
    } else {
      setName('');
      setDescription('');
      setRuleType('TOOL_RESTRICTION');
      setTargetTools('*');
      setTargetServers('*');
      setRiskThreshold(75);
      setAction('BLOCK');
      setEnabled(true);
    }
    setIsConfirming(false);
    setFeedback(null);
  }, [policy, isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setFeedback({ type: 'error', message: 'Policy name is required.' });
      return;
    }
    if (!targetTools.trim()) {
      setFeedback({ type: 'error', message: 'Target tools pattern is required.' });
      return;
    }

    if (!isConfirming) {
      setIsConfirming(true);
      return;
    }

    setIsSubmitting(true);
    setFeedback(null);

    const toolsArr = targetTools.split(',').map((s) => s.trim()).filter(Boolean);
    const serversArr = targetServers.split(',').map((s) => s.trim()).filter(Boolean);

    let res: { success: boolean; message: string };

    if (isNew || !policy) {
      res = await addPolicy({
        name,
        description,
        ruleType,
        targetTools: toolsArr,
        targetServers: serversArr,
        riskThreshold,
        action,
        enabled,
        author: 'analyst@agentguard.internal',
      });
    } else {
      res = await updatePolicy({
        ...policy,
        name,
        description,
        ruleType,
        targetTools: toolsArr,
        targetServers: serversArr,
        riskThreshold,
        action,
        enabled,
      });
    }

    setIsSubmitting(false);

    if (res.success) {
      setFeedback({ type: 'success', message: res.message });
      setTimeout(() => {
        onClose();
      }, 1200);
    } else {
      setFeedback({ type: 'error', message: res.message });
      setIsConfirming(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isNew ? 'Create New Security Policy' : `Edit Policy: ${policy?.id || ''}`}
      subtitle="Configure runtime enforcement rules and risk score quarantine thresholds."
      maxWidth="max-w-2xl"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {feedback && (
          <div
            className={`p-3 rounded-lg text-xs flex items-start gap-2 border ${
              feedback.type === 'success'
                ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
                : 'bg-rose-950/40 text-rose-300 border-rose-500/30'
            }`}
          >
            {feedback.type === 'success' ? (
              <CheckCircle2 size={16} className="text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <AlertTriangle size={16} className="text-rose-400 shrink-0 mt-0.5" />
            )}
            <span>{feedback.message}</span>
          </div>
        )}

        {/* Name */}
        <div>
          <label className="text-xs font-medium text-slate-300 block mb-1">
            Policy Name *
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., Block Shell Command Execution"
            className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500"
            required
          />
        </div>

        {/* Description */}
        <div>
          <label className="text-xs font-medium text-slate-300 block mb-1">
            Description
          </label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder="Operational purpose and threat mitigations..."
            className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500"
          />
        </div>

        {/* Grid: Rule Type & Action */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Rule Type
            </label>
            <select
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value as PolicyRule['ruleType'])}
              className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-hidden focus:border-cyan-500"
            >
              <option value="TOOL_RESTRICTION">TOOL_RESTRICTION (Block specific tools)</option>
              <option value="PARAMETER_INSPECTION">PARAMETER_INSPECTION (Path/payload regex)</option>
              <option value="RISK_THRESHOLD">RISK_THRESHOLD (Score quarantine)</option>
              <option value="RESPONSE_DLP">RESPONSE_DLP (Data Loss Prevention)</option>
              <option value="PROMPT_SAFETY">PROMPT_SAFETY (Jailbreak detection)</option>
            </select>
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Enforcement Action
            </label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value as DecisionType)}
              className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-hidden focus:border-cyan-500"
            >
              <option value="BLOCK">BLOCK (Halt invocation pre-execution)</option>
              <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL (Quarantine for human review)</option>
              <option value="REDACT">REDACT (Sanitize sensitive output payload)</option>
              <option value="ALLOW">ALLOW (Explicit whitelist pass)</option>
            </select>
          </div>
        </div>

        {/* Targets */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Target Tools (comma separated)
            </label>
            <input
              type="text"
              value={targetTools}
              onChange={(e) => setTargetTools(e.target.value)}
              placeholder="e.g., filesystem/*, shell/exec"
              className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-400 font-mono focus:outline-hidden focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1">
              Target MCP Servers
            </label>
            <input
              type="text"
              value={targetServers}
              onChange={(e) => setTargetServers(e.target.value)}
              placeholder="e.g., *, filesystem-mcp"
              className="w-full px-3 py-2 bg-[#080d16] border border-slate-800 rounded-lg text-xs text-slate-100 placeholder-slate-400 font-mono focus:outline-hidden focus:border-cyan-500"
            />
          </div>
        </div>

        {/* Risk Threshold Slider */}
        <div className="space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-slate-300">Risk Threshold Trigger:</span>
            <span className="font-mono text-cyan-400 font-bold">{riskThreshold}/100</span>
          </div>
          <input
            type="range"
            min={1}
            max={100}
            value={riskThreshold}
            onChange={(e) => setRiskThreshold(Number(e.target.value))}
            className="w-full accent-cyan-500 cursor-pointer"
          />
          <span className="text-[11px] text-slate-400 block">
            Calls with computed risk equal to or above this score will trigger the action.
          </span>
        </div>

        {/* Enabled Toggle */}
        <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-900/40">
          <div>
            <span className="text-xs font-medium text-slate-200 block">Policy Status</span>
            <span className="text-[11px] text-slate-400">
              When disabled, this rule is skipped during gateway evaluation.
            </span>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-slate-800 peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500" />
          </label>
        </div>

        {/* Confirmation Step */}
        {isConfirming && (
          <div className="p-3.5 rounded-lg border border-amber-500/40 bg-amber-950/30 text-xs text-amber-200 space-y-1">
            <div className="flex items-center gap-2 font-semibold">
              <AlertTriangle size={15} className="text-amber-400" />
              <span>Confirm Policy Modification</span>
            </div>
            <p>
              Are you sure you want to enforce <strong>{action}</strong> when risk &ge; {riskThreshold} on tools ({targetTools})?
            </p>
          </div>
        )}

        {/* Actions */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
              isConfirming
                ? 'bg-amber-600 hover:bg-amber-500 text-white'
                : 'bg-cyan-600 hover:bg-cyan-500 text-white'
            }`}
          >
            <Shield size={14} />
            <span>
              {isSubmitting
                ? 'Saving...'
                : isConfirming
                ? 'Confirm & Deploy Policy'
                : 'Review & Save'}
            </span>
          </button>
        </div>
      </form>
    </Modal>
  );
};
