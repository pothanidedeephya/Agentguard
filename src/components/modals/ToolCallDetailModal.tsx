import React, { useState } from 'react';
import { Modal } from '../common/Modal';
import { DecisionBadge } from '../common/DecisionBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { CodeBlock } from '../common/CodeBlock';
import { ToolCall } from '../../types/agentguard';
import { Clock, Shield, Database, Cpu, Terminal, AlertTriangle, CheckCircle2 } from 'lucide-react';

interface ToolCallDetailModalProps {
  toolCall: ToolCall | null;
  onClose: () => void;
}

export const ToolCallDetailModal: React.FC<ToolCallDetailModalProps> = ({
  toolCall,
  onClose,
}) => {
  const [activeTab, setActiveTab] = useState<'input' | 'security' | 'output'>('input');

  if (!toolCall) return null;

  const isBlockedPreExecution = toolCall.status === 'BLOCKED';
  const isPostExecFlagged = toolCall.status === 'FLAGGED_POST_EXEC';

  return (
    <Modal
      isOpen={!!toolCall}
      onClose={onClose}
      title={`Tool Call Forensics: ${toolCall.id}`}
      subtitle={`Intercepted from agent "${toolCall.agentName}" targeting MCP tool "${toolCall.toolName}"`}
      maxWidth="max-w-3xl"
    >
      <div className="space-y-4">
        {/* Top Summary Header Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg border border-slate-800 bg-[#070c16]">
          <div>
            <span className="text-[11px] text-slate-400 block">Policy Decision</span>
            <div className="mt-1">
              <DecisionBadge decision={toolCall.decision} size="sm" />
            </div>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Risk Score</span>
            <div className="mt-1">
              <RiskScoreBadge score={toolCall.riskScore} />
            </div>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Execution Lifecycle</span>
            <span className={`text-xs font-mono font-semibold block mt-1 ${
              isBlockedPreExecution
                ? 'text-rose-400'
                : toolCall.status === 'PENDING_APPROVAL'
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}>
              {toolCall.status}
            </span>
          </div>
          <div>
            <span className="text-[11px] text-slate-400 block">Latency & Timestamp</span>
            <span className="text-xs font-mono text-slate-200 block mt-1">
              {toolCall.durationMs}ms · {new Date(toolCall.timestamp).toLocaleTimeString()}
            </span>
          </div>
        </div>

        {/* Execution distinction banner */}
        {isBlockedPreExecution && (
          <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-950/20 text-xs text-rose-300 flex items-start gap-2">
            <Shield size={16} className="text-rose-400 mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold">Execution Blocked Pre-Invocation: </span>
              The MCP client invocation was halted prior to reaching the MCP server runtime. No untrusted execution occurred.
            </div>
          </div>
        )}

        {isPostExecFlagged && (
          <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-xs text-amber-300 flex items-start gap-2">
            <AlertTriangle size={16} className="text-amber-400 mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold">Flagged Post-Execution: </span>
              The tool was invoked, but response data triggered security heuristics during egress inspection.
            </div>
          </div>
        )}

        {/* Metadata Strip */}
        <div className="text-xs text-slate-400 flex flex-wrap gap-x-4 gap-y-1.5 p-2.5 rounded-lg border border-slate-800/80 bg-slate-900/40 font-mono">
          <span>Agent ID: <strong className="text-slate-200">{toolCall.agentId}</strong></span>
          <span>MCP Server: <strong className="text-slate-200">{toolCall.serverName}</strong></span>
          <span>Tool: <strong className="text-cyan-300">{toolCall.toolName}</strong></span>
          <span>Audit Ref: <strong className="text-slate-200">{toolCall.auditId}</strong></span>
        </div>

        {/* Forensic Tabs */}
        <div className="flex items-center gap-1 border-b border-slate-800 pb-1">
          <button
            onClick={() => setActiveTab('input')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'input'
                ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Input Parameters
          </button>
          <button
            onClick={() => setActiveTab('security')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'security'
                ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Detection Reasons & Checks ({toolCall.detectionReasons.length})
          </button>
          <button
            onClick={() => setActiveTab('output')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
              activeTab === 'output'
                ? 'bg-slate-800 text-cyan-300 border border-slate-700'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Tool Output & DLP
          </button>
        </div>

        {/* Tab 1: Input Parameters */}
        {activeTab === 'input' && (
          <div className="space-y-3">
            <div>
              <span className="text-xs font-semibold text-slate-300 block mb-1">
                Original Input Parameters
              </span>
              <CodeBlock
                code={toolCall.inputParams}
                title="tool_invocation_arguments.json"
              />
            </div>
            {toolCall.normalizedParams && (
              <div>
                <span className="text-xs font-semibold text-slate-300 block mb-1">
                  Normalized / Resolved Arguments (Sandbox Path)
                </span>
                <CodeBlock
                  code={toolCall.normalizedParams}
                  title="normalized_sandbox_arguments.json"
                />
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Security Checks */}
        {activeTab === 'security' && (
          <div className="space-y-2">
            <span className="text-xs font-semibold text-slate-300 block">
              Enforcement Heuristics & Rules Triggered
            </span>
            {toolCall.detectionReasons.map((reason, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg border border-slate-800 bg-slate-900/60 text-xs text-slate-300 flex items-start gap-2.5 font-mono"
              >
                <span className="text-cyan-400 font-bold shrink-0">{`#0${idx + 1}`}</span>
                <span>{reason}</span>
              </div>
            ))}
          </div>
        )}

        {/* Tab 3: Output */}
        {activeTab === 'output' && (
          <div className="space-y-3">
            {toolCall.status === 'BLOCKED' ? (
              <div className="p-4 text-center rounded-lg border border-dashed border-slate-800 bg-slate-950/40 text-xs text-slate-400">
                No tool output returned. Call was blocked by AgentGuard before execution.
              </div>
            ) : (
              <>
                {toolCall.redactedOutput && (
                  <div>
                    <span className="text-xs font-semibold text-purple-300 block mb-1 flex items-center gap-1.5">
                      <Shield size={12} className="text-purple-400" />
                      Sanitized Output Delivered to Agent (DLP Applied)
                    </span>
                    <CodeBlock
                      code={toolCall.redactedOutput}
                      title="dlp_sanitized_response.json"
                    />
                  </div>
                )}
                {toolCall.outputData && (
                  <div>
                    <span className="text-xs font-semibold text-slate-300 block mb-1">
                      Raw Output Payload
                    </span>
                    <CodeBlock
                      code={toolCall.outputData}
                      title="raw_mcp_output.json"
                    />
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Bottom Footer Actions */}
        <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
          <span className="text-[11px] text-slate-400 font-mono">
            Audit ID: {toolCall.auditId} · Immutable Event Record
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Close Forensics
          </button>
        </div>
      </div>
    </Modal>
  );
};
