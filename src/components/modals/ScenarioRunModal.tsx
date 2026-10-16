import React, { useState } from 'react';
import { Modal } from '../common/Modal';
import { DecisionBadge } from '../common/DecisionBadge';
import { useSecurity } from '../../context/SecurityContext';
import { Play, CheckCircle2, Shield, AlertTriangle } from 'lucide-react';
import { ToolCall } from '../../types/agentguard';

interface ScenarioRunModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ScenarioRunModal: React.FC<ScenarioRunModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { scenarios, runScenario, setSelectedToolCall, setCurrentPage } = useSecurity();
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastExecutedCall, setLastExecutedCall] = useState<ToolCall | null>(null);

  const handleExecute = async (scenarioId: string) => {
    setRunningId(scenarioId);
    try {
      const call = await runScenario(scenarioId);
      setLastExecutedCall(call);
    } catch {
      // error handled
    } finally {
      setRunningId(null);
    }
  };

  const handleInspect = (call: ToolCall) => {
    setSelectedToolCall(call);
    onClose();
    setCurrentPage('tool-calls');
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Deterministic Security Scenario Runner"
      subtitle="Execute verified runtime defence scenarios against MCP tools to observe real-time policy evaluation and SOC response."
      maxWidth="max-w-3xl"
    >
      <div className="space-y-4">
        {lastExecutedCall && (
          <div className="p-3.5 rounded-lg border border-cyan-500/40 bg-cyan-950/20 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <CheckCircle2 size={18} className="text-cyan-400 shrink-0" />
              <div>
                <p className="text-xs font-semibold text-cyan-200">
                  Scenario Evaluated:{' '}
                  <span className="font-mono">{lastExecutedCall.toolName}</span> ({lastExecutedCall.agentName})
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Result: <DecisionBadge decision={lastExecutedCall.decision} size="sm" /> · Risk {lastExecutedCall.riskScore}/100 · Latency {lastExecutedCall.durationMs}ms
                </p>
              </div>
            </div>
            <button
              onClick={() => handleInspect(lastExecutedCall)}
              className="text-xs font-medium text-cyan-300 hover:text-cyan-100 underline shrink-0"
            >
              Inspect Call Forensics
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 gap-3">
          {scenarios.map((scen) => (
            <div
              key={scen.id}
              className="p-3.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-slate-700 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold text-slate-100">
                    {scen.name}
                  </span>
                  <span className="text-[11px] text-slate-400 font-mono">
                    [{scen.category}]
                  </span>
                  <span className="text-[11px] text-slate-400">Target:</span>
                  <DecisionBadge decision={scen.expectedDecision} size="sm" />
                </div>
                <p className="text-xs text-slate-400">
                  {scen.description}
                </p>
                <div className="font-mono text-[11px] text-slate-400">
                  Tool: <span className="text-slate-300">{scen.payload.serverName}/{scen.payload.toolName}</span> · Agent: <span className="text-slate-300">{scen.payload.agentName}</span>
                </div>
              </div>

              <div className="shrink-0 flex items-center gap-2">
                <button
                  onClick={() => handleExecute(scen.id)}
                  disabled={runningId !== null}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-xs"
                >
                  <Play size={12} className={runningId === scen.id ? 'animate-spin' : ''} />
                  <span>{runningId === scen.id ? 'Evaluating...' : 'Dispatch'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="p-3 rounded-lg border border-slate-800/80 bg-slate-950/60 text-[11px] text-slate-400 flex items-start gap-2">
          <Shield size={14} className="text-cyan-400 mt-0.5 shrink-0" />
          <span>
            Scenarios dispatch directly to the AgentGuard evaluation engine. If a live gateway is connected, evaluation requests are routed to <code className="text-slate-300 font-mono">POST /api/evaluate</code>; otherwise, deterministic local rules process the tool calls and update the active SOC monitor and threat tables.
          </span>
        </div>
      </div>
    </Modal>
  );
};
