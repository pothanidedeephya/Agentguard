import React, { useState } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { DecisionBadge } from '../common/DecisionBadge';
import { ThreatSeverityBadge } from '../common/ThreatSeverityBadge';
import { PolicyRule, DecisionType, ThreatSeverity } from '../../types/agentguard';
import { PolicyEditModal } from '../modals/PolicyEditModal';
import {
  Scale,
  Plus,
  Edit2,
  CheckCircle2,
  ShieldAlert,
  Play,
  RotateCcw,
  AlertTriangle,
  Server,
  Terminal,
  Shield,
} from 'lucide-react';
import { agentGuardApi } from '../../services/api';

// Map rule types / thresholds to standard severity levels for policy overview
function getPolicySeverity(policy: PolicyRule): ThreatSeverity {
  if (policy.riskThreshold >= 90 || policy.action === 'BLOCK') return 'CRITICAL';
  if (policy.riskThreshold >= 70 || policy.action === 'REQUIRE_APPROVAL') return 'HIGH';
  if (policy.riskThreshold >= 40 || policy.action === 'REDACT') return 'MEDIUM';
  return 'LOW';
}

export const PolicyEnginePage: React.FC = () => {
  const { policies, updatePolicy, isBackendConnected } = useSecurity();

  const [selectedPolicy, setSelectedPolicy] = useState<PolicyRule | null>(null);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isNewPolicy, setIsNewPolicy] = useState(false);
  const [policyFilter, setPolicyFilter] = useState<'ALL' | 'ENABLED' | 'DISABLED'>('ALL');

  // Policy Evaluation Sandbox State
  const [testTool, setTestTool] = useState('filesystem/read_file');
  const [testAgent, setTestAgent] = useState('CodeReviewAgent');
  const [testParams, setTestParams] = useState('{\n  "path": "../../../../etc/passwd"\n}');
  const [evaluating, setEvaluating] = useState(false);
  const [evalResult, setEvalResult] = useState<{
    decision: DecisionType;
    riskScore: number;
    reasons: string[];
  } | null>(null);

  const handleToggleEnable = async (policy: PolicyRule) => {
    await updatePolicy({
      ...policy,
      enabled: !policy.enabled,
    });
  };

  const handleEdit = (policy: PolicyRule) => {
    setSelectedPolicy(policy);
    setIsNewPolicy(false);
    setIsEditModalOpen(true);
  };

  const handleCreate = () => {
    setSelectedPolicy(null);
    setIsNewPolicy(true);
    setIsEditModalOpen(true);
  };

  const filteredPolicies = policies.filter((p) => {
    if (policyFilter === 'ENABLED') return p.enabled;
    if (policyFilter === 'DISABLED') return !p.enabled;
    return true;
  });

  const handleRunEvaluation = async () => {
    setEvaluating(true);
    setEvalResult(null);

    let parsedParams = {};
    try {
      parsedParams = JSON.parse(testParams);
    } catch {
      alert('Invalid JSON in test parameters.');
      setEvaluating(false);
      return;
    }

    if (isBackendConnected) {
      try {
        const res = await agentGuardApi.evaluateToolCall({
          agentId: testAgent,
          serverName: testTool.split('/')[0] || 'filesystem-mcp',
          toolName: testTool.split('/')[1] || testTool,
          parameters: parsedParams,
        });
        setEvalResult({
          decision: res.decision,
          riskScore: res.riskScore,
          reasons: res.reasons || ['Evaluated by gateway live rules engine'],
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Evaluation failed';
        alert(`Evaluation error: ${msg}`);
      }
    } else {
      setTimeout(() => {
        const pString = JSON.stringify(parsedParams);
        let dec: DecisionType = 'ALLOW';
        let score = 10;
        const reasons: string[] = [];

        if (pString.includes('..') || pString.includes('/etc/')) {
          dec = 'BLOCK';
          score = 98;
          reasons.push('Matched Policy pol-001 (Directory Traversal & Path Quarantine)');
          reasons.push('Relative path climbing pattern detected');
        } else if (pString.includes('rm -rf') || pString.includes('curl')) {
          dec = 'BLOCK';
          score = 100;
          reasons.push('Matched Policy pol-002 (Arbitrary Shell Execution Quarantine)');
        } else if (pString.toLowerCase().includes('drop table')) {
          dec = 'REQUIRE_APPROVAL';
          score = 94;
          reasons.push('Matched Policy pol-003 (Database Destructive DDL Guard)');
        } else {
          reasons.push('All parameters verified within safe constraints');
        }

        setEvalResult({ decision: dec, riskScore: score, reasons });
        setEvaluating(false);
      }, 350);
      return;
    }

    setEvaluating(false);
  };

  return (
    <div className="space-y-4">
      {/* Policy Engine Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <Scale size={15} className="text-cyan-400" />
            Security Policies & Runtime Governance
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Configured deterministic rules enforcing ALLOW, BLOCK, REQUIRE_APPROVAL, and REDACT actions
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Segmented Filter */}
          <div className="flex items-center p-0.5 bg-slate-900 border border-slate-800 rounded text-[11px] font-mono">
            {(['ALL', 'ENABLED', 'DISABLED'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setPolicyFilter(f)}
                className={`px-2 py-0.5 rounded transition-colors ${
                  policyFilter === f
                    ? 'bg-slate-800 text-cyan-300 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          <button
            onClick={handleCreate}
            className="flex items-center gap-1.5 px-3 py-1 rounded bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-mono transition-colors shrink-0"
          >
            <Plus size={13} />
            <span>New Rule</span>
          </button>
        </div>
      </div>

      {/* Structured Policies Table / Grid */}
      <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#080d17] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Rule Name & ID</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">Enforcement Action</th>
                <th className="py-2.5 px-3">Scope (Tools / Servers)</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {filteredPolicies.map((policy) => {
                const severity = getPolicySeverity(policy);

                return (
                  <tr
                    key={policy.id}
                    className={`hover:bg-slate-850/50 transition-colors ${
                      !policy.enabled ? 'opacity-60 bg-[#070b14]' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="text-cyan-400 font-bold">{policy.id}</div>
                      <div className="text-slate-100 font-sans font-semibold text-xs">
                        {policy.name}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">
                        {policy.ruleType}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <ThreatSeverityBadge severity={severity} />
                    </td>
                    <td className="py-2.5 px-3 max-w-[260px] text-slate-300 font-sans text-xs">
                      {policy.description}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <DecisionBadge decision={policy.action} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[10px]">
                      <div>Tools: {policy.targetTools.join(', ')}</div>
                      <div>Servers: {policy.targetServers.join(', ')}</div>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={policy.enabled}
                          onChange={() => handleToggleEnable(policy)}
                          className="sr-only peer"
                        />
                        <div className="w-7 h-3.5 bg-slate-800 peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:bg-emerald-500" />
                        <span className="ml-2 text-[10px] font-mono text-slate-300">
                          {policy.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </label>
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleEdit(policy)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px] transition-colors"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sandbox Tester */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
            <Terminal size={14} className="text-cyan-400" />
            Policy Dry-Run Sandbox
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Test arbitrary MCP parameter payloads against active policy rules without dispatching to real servers
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="space-y-2.5 text-xs">
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                  Target MCP Tool:
                </label>
                <input
                  type="text"
                  value={testTool}
                  onChange={(e) => setTestTool(e.target.value)}
                  className="w-full px-2 py-1 bg-[#080d17] border border-slate-800 rounded text-xs font-mono text-slate-200"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                  Simulated Agent:
                </label>
                <input
                  type="text"
                  value={testAgent}
                  onChange={(e) => setTestAgent(e.target.value)}
                  className="w-full px-2 py-1 bg-[#080d17] border border-slate-800 rounded text-xs font-mono text-slate-200"
                />
              </div>
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                Input Parameters (JSON):
              </label>
              <textarea
                value={testParams}
                onChange={(e) => setTestParams(e.target.value)}
                rows={3}
                className="w-full p-2 bg-[#080d17] border border-slate-800 rounded text-xs font-mono text-cyan-300 focus:outline-hidden focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleRunEvaluation}
              disabled={evaluating}
              className="px-3 py-1.5 rounded bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-xs font-mono transition-colors flex items-center gap-1.5"
            >
              <Play size={12} className={evaluating ? 'animate-spin' : ''} />
              <span>{evaluating ? 'Evaluating Rules...' : 'Run Dry-Run Evaluation'}</span>
            </button>
          </div>

          {/* Result Output */}
          <div className="p-3 rounded border border-slate-800 bg-[#080d17] flex flex-col justify-between text-xs font-mono">
            <div>
              <span className="text-[10px] uppercase text-slate-400 block mb-2 font-semibold">
                Evaluation Verdict:
              </span>
              {evalResult ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2.5">
                    <DecisionBadge decision={evalResult.decision} size="sm" />
                    <span className="text-slate-300">
                      Risk Score: <strong className="text-white">{evalResult.riskScore}</strong>/100
                    </span>
                  </div>
                  <div className="space-y-1">
                    <span className="text-[10px] text-slate-400 block uppercase">Matched Rules:</span>
                    {evalResult.reasons.map((r, i) => (
                      <div
                        key={i}
                        className="text-[11px] text-slate-300 bg-slate-900/80 p-1.5 rounded border border-slate-800"
                      >
                        {r}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="h-24 flex items-center justify-center text-slate-400 text-center text-xs">
                  Click &ldquo;Run Dry-Run Evaluation&rdquo; to test parameters against the policy rules engine.
                </div>
              )}
            </div>

            <div className="text-[10px] text-slate-400 pt-2 border-t border-slate-800/80">
              {isBackendConnected ? 'Active Gateway daemon connection' : 'Local deterministic policy matrix'}
            </div>
          </div>
        </div>
      </div>

      {/* Modal */}
      <PolicyEditModal
        policy={selectedPolicy}
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
        isNew={isNewPolicy}
      />
    </div>
  );
};
