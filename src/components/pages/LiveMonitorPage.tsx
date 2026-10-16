import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { DecisionBadge } from '../common/DecisionBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { CodeBlock } from '../common/CodeBlock';
import {
  Activity,
  Pause,
  Play,
  Trash2,
  Search,
  ChevronDown,
  ChevronUp,
  Radio,
  ExternalLink,
  Shield,
  Zap,
  Server,
  Database,
  CheckCircle2,
} from 'lucide-react';
import { ToolCall, DecisionType } from '../../types/agentguard';

export const LiveMonitorPage: React.FC = () => {
  const {
    toolCalls,
    isLiveStreamActive,
    setIsLiveStreamActive,
    streamSpeedSeconds,
    setStreamSpeedSeconds,
    clearLiveStream,
    isBackendConnected,
    dbState,
    dbHost,
    operatingState,
    setSelectedToolCall,
  } = useSecurity();

  const [expandedCallId, setExpandedCallId] = useState<string | null>(null);
  const [filterText, setFilterText] = useState('');
  const [selectedDecision, setSelectedDecision] = useState<string>('ALL');
  const [minRisk, setMinRisk] = useState<number>(0);

  const toggleExpand = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setExpandedCallId((prev) => (prev === id ? null : id));
  };

  const filteredStream = useMemo(() => {
    return toolCalls.filter((c) => {
      const matchText =
        c.toolName.toLowerCase().includes(filterText.toLowerCase()) ||
        c.agentName.toLowerCase().includes(filterText.toLowerCase()) ||
        c.serverName.toLowerCase().includes(filterText.toLowerCase()) ||
        c.id.toLowerCase().includes(filterText.toLowerCase());

      const matchDecision =
        selectedDecision === 'ALL' || c.decision === selectedDecision;

      const matchRisk = c.riskScore >= minRisk;

      return matchText && matchDecision && matchRisk;
    });
  }, [toolCalls, filterText, selectedDecision, minRisk]);

  const isLive = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  return (
    <div className="space-y-4">
      {/* Top Stream Control Console */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        {/* Stream Status and Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                isLiveStreamActive ? 'bg-emerald-400' : 'bg-slate-500'
              }`}
            />
            <span className="text-xs font-semibold text-slate-100">
              {isLiveStreamActive ? 'Live Ingestion Active' : 'Ingestion Suspended'}
            </span>
          </div>

          <span className="text-slate-600 font-mono">|</span>

          <span
            className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              isLive
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                : 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300'
            }`}
          >
            {isLive ? `PostgreSQL Daemon (${dbHost || 'Supabase'})` : 'Local Buffer Stream'}
          </span>
        </div>

        {/* Action Buttons: Pause/Resume, Speed, Clear */}
        <div className="flex items-center gap-2 flex-wrap font-mono text-[11px]">
          <button
            onClick={() => setIsLiveStreamActive(!isLiveStreamActive)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded border transition-colors ${
              isLiveStreamActive
                ? 'bg-amber-950/50 hover:bg-amber-900/50 text-amber-300 border-amber-500/40'
                : 'bg-emerald-950/50 hover:bg-emerald-900/50 text-emerald-300 border-emerald-500/40'
            }`}
          >
            {isLiveStreamActive ? <Pause size={12} /> : <Play size={12} />}
            <span>{isLiveStreamActive ? 'Pause Stream' : 'Resume'}</span>
          </button>

          {/* Stream Rate Selector */}
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded p-0.5">
            <span className="px-1.5 text-slate-400 text-[10px]">Rate:</span>
            {[2, 4, 8].map((sec) => (
              <button
                key={sec}
                onClick={() => setStreamSpeedSeconds(sec)}
                className={`px-1.5 py-0.5 rounded transition-colors ${
                  streamSpeedSeconds === sec
                    ? 'bg-slate-800 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sec}s
              </button>
            ))}
          </div>

          <button
            onClick={clearLiveStream}
            className="p-1 text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors"
            title="Flush buffer"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col lg:flex-row lg:items-center justify-between gap-2.5 text-xs">
        <div className="flex items-center gap-2 flex-1">
          <div className="relative flex-1 max-w-sm">
            <Search size={13} className="absolute left-2.5 top-2 text-slate-400" />
            <input
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder="Filter live stream by tool, agent, ID..."
              className="w-full pl-8 pr-3 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500 font-mono"
            />
          </div>

          <select
            value={selectedDecision}
            onChange={(e) => setSelectedDecision(e.target.value)}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW only</option>
            <option value="BLOCK">BLOCK only</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL only</option>
            <option value="REDACT">REDACT only</option>
          </select>
        </div>

        <div className="flex items-center gap-2.5 font-mono text-[11px]">
          <span className="text-slate-400 whitespace-nowrap">
            Min Risk: <strong className="text-cyan-400">{minRisk}</strong>
          </span>
          <input
            type="range"
            min={0}
            max={90}
            step={10}
            value={minRisk}
            onChange={(e) => setMinRisk(Number(e.target.value))}
            className="w-24 sm:w-28 accent-cyan-500 cursor-pointer"
          />
        </div>
      </div>

      {/* Live Event Stream Feed */}
      <div className="space-y-1.5">
        {filteredStream.length === 0 ? (
          <div className="p-12 text-center rounded-lg border border-dashed border-slate-800 bg-[#0d1424] space-y-1">
            <Activity size={20} className="mx-auto text-slate-500" />
            <p className="text-xs font-medium text-slate-300 font-mono">
              No live telemetry matching filter
            </p>
            <p className="text-[11px] text-slate-400">
              Adjust minimum risk threshold or resume ingestion stream.
            </p>
          </div>
        ) : (
          filteredStream.map((call) => {
            const isExpanded = expandedCallId === call.id;

            return (
              <div
                key={call.id}
                className="rounded-lg border border-slate-800/90 bg-[#0d1424] hover:border-slate-700 transition-colors overflow-hidden"
              >
                {/* Event Summary Bar */}
                <div
                  onClick={() => setSelectedToolCall(call)}
                  className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 cursor-pointer select-none text-xs font-mono"
                >
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-slate-400 text-[11px]">
                      {new Date(call.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-cyan-400 font-semibold">{call.id}</span>

                    <DecisionBadge decision={call.decision} size="sm" />
                    <RiskScoreBadge score={call.riskScore} showLabel={false} />

                    <div className="text-slate-200">
                      <span className="font-semibold">{call.toolName}</span>
                      <span className="text-slate-400"> on </span>
                      <span className="text-slate-400">{call.serverName}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 text-[11px] text-slate-400">
                    <span>{call.durationMs}ms</span>
                    <span>
                      Agent: <strong className="text-slate-200">{call.agentName}</strong>
                    </span>
                    <button
                      onClick={(e) => toggleExpand(call.id, e)}
                      className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                      title={isExpanded ? 'Collapse' : 'Expand payload'}
                    >
                      {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                  </div>
                </div>

                {/* Inline Drawer */}
                {isExpanded && (
                  <div className="px-3.5 pb-3.5 pt-1 border-t border-slate-800/80 bg-[#080d17] space-y-2 text-xs">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                      <div>
                        <span className="text-slate-400 block mb-1 font-mono text-[10px] uppercase">
                          Input Parameters:
                        </span>
                        <CodeBlock code={call.inputParams} maxHeight="max-h-32" />
                      </div>
                      <div className="space-y-1.5">
                        <span className="text-slate-400 block font-mono text-[10px] uppercase">
                          Detection Rationale:
                        </span>
                        {call.detectionReasons.map((r, i) => (
                          <div
                            key={i}
                            className="p-1.5 rounded border border-slate-800 bg-slate-900/60 text-slate-300 font-mono text-[11px]"
                          >
                            {r}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
