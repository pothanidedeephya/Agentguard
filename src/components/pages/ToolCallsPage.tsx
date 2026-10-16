import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { DecisionBadge } from '../common/DecisionBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { ToolCall, DecisionType } from '../../types/agentguard';
import {
  Terminal,
  Search,
  Filter,
  Download,
  AlertTriangle,
  ExternalLink,
  ShieldAlert,
  Clock,
  EyeOff,
  Calendar,
} from 'lucide-react';

// Sanitize parameter preview to prevent leaking API keys, passwords, tokens, or private secrets in table
function redactSensitivePreview(params: Record<string, unknown>): string {
  try {
    const serialized = JSON.stringify(params);
    // Mask potential API keys, passwords, tokens
    return serialized
      .replace(/("sk-[a-zA-Z0-9_-]{8})[a-zA-Z0-9_-]+"/g, '$1..." [REDACTED]')
      .replace(/("AKIA[0-9A-Z]{4})[0-9A-Z]+"/g, '$1..." [REDACTED]')
      .replace(/("(?:password|secret|token|apiKey|api_key|auth)":\s*")[^"]+(")/gi, '$1***REDACTED***$2');
  } catch {
    return '{...}';
  }
}

export const ToolCallsPage: React.FC = () => {
  const { toolCalls, setSelectedToolCall, mcpServers, isBackendConnected } = useSecurity();

  const [searchTerm, setSearchTerm] = useState('');
  const [selectedServer, setSelectedServer] = useState<string>('ALL');
  const [selectedDecision, setSelectedDecision] = useState<string>('ALL');
  const [minRisk, setMinRisk] = useState<number>(0);
  const [timeFilter, setTimeFilter] = useState<'ALL' | '1h' | '24h' | '7d'>('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const filteredCalls = useMemo(() => {
    const now = Date.now();
    return toolCalls.filter((call) => {
      const matchSearch =
        call.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        call.toolName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        call.agentName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        call.serverName.toLowerCase().includes(searchTerm.toLowerCase()) ||
        JSON.stringify(call.inputParams).toLowerCase().includes(searchTerm.toLowerCase());

      const matchServer =
        selectedServer === 'ALL' || call.serverName === selectedServer;

      const matchDecision =
        selectedDecision === 'ALL' || call.decision === selectedDecision;

      const matchRisk = call.riskScore >= minRisk;

      let matchTime = true;
      if (timeFilter !== 'ALL') {
        const callTime = new Date(call.timestamp).getTime();
        const diffMs = now - callTime;
        if (timeFilter === '1h') matchTime = diffMs <= 3600 * 1000;
        else if (timeFilter === '24h') matchTime = diffMs <= 24 * 3600 * 1000;
        else if (timeFilter === '7d') matchTime = diffMs <= 7 * 24 * 3600 * 1000;
      }

      return matchSearch && matchServer && matchDecision && matchRisk && matchTime;
    });
  }, [toolCalls, searchTerm, selectedServer, selectedDecision, minRisk, timeFilter]);

  const totalPages = Math.ceil(filteredCalls.length / pageSize) || 1;
  const paginatedCalls = filteredCalls.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-4">
      {/* Investigation Controls Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <Terminal size={15} className="text-cyan-400" />
            Tool Request Monitoring & Forensics
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Real-time interception of Model Context Protocol (MCP) tool invocations across all active agents
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-[11px] text-slate-400">
          <span>
            Indexed Requests: <strong className="text-slate-100">{toolCalls.length}</strong>
          </span>
          <span>·</span>
          <span>
            Filtered: <strong className="text-cyan-300">{filteredCalls.length}</strong>
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-wrap items-center justify-between gap-2.5 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px] flex-wrap sm:flex-nowrap">
          {/* Search */}
          <div className="relative flex-1 min-w-[180px]">
            <Search size={13} className="absolute left-2.5 top-2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Search request ID, tool, agent, payload..."
              className="w-full pl-8 pr-3 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500 font-mono"
            />
          </div>

          {/* MCP Server Filter */}
          <select
            value={selectedServer}
            onChange={(e) => {
              setSelectedServer(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All MCP Servers</option>
            {mcpServers.map((s) => (
              <option key={s.id} value={s.name}>
                {s.name}
              </option>
            ))}
          </select>

          {/* Decision Filter */}
          <select
            value={selectedDecision}
            onChange={(e) => {
              setSelectedDecision(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="REDACT">REDACT</option>
          </select>

          {/* Time Range Filter */}
          <select
            value={timeFilter}
            onChange={(e) => {
              setTimeFilter(e.target.value as any);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Time</option>
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>

        {/* Risk Threshold Slider */}
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
            onChange={(e) => {
              setMinRisk(Number(e.target.value));
              setPage(1);
            }}
            className="w-24 sm:w-28 accent-cyan-500 cursor-pointer"
          />
        </div>
      </div>

      {/* Main Table: Professional SOC Format */}
      <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#080d17] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Request ID</th>
                <th className="py-2.5 px-3">Tool Name</th>
                <th className="py-2.5 px-3">Operation / Server</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Security Decision</th>
                <th className="py-2.5 px-3">Execution Status</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {paginatedCalls.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 text-xs">
                    No tool requests matching the specified criteria.
                  </td>
                </tr>
              ) : (
                paginatedCalls.map((call) => {
                  const sanitizedSnippet = redactSensitivePreview(call.inputParams);
                  const isBlocked = call.status === 'BLOCKED';

                  return (
                    <tr
                      key={call.id}
                      onClick={() => setSelectedToolCall(call)}
                      className="hover:bg-slate-850/50 cursor-pointer transition-colors group"
                    >
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {new Date(call.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold whitespace-nowrap group-hover:underline">
                        {call.id}
                      </td>
                      <td className="py-2.5 px-3 text-slate-100 font-semibold whitespace-nowrap">
                        {call.toolName}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                        <span className="text-slate-400">{call.serverName}</span>
                        <span className="text-slate-600 mx-1.5">/</span>
                        <span className="text-slate-200">{call.agentName}</span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <RiskScoreBadge score={call.riskScore} />
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <DecisionBadge decision={call.decision} size="sm" />
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-semibold ${
                            isBlocked
                              ? 'text-rose-400'
                              : call.status === 'PENDING_APPROVAL'
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {call.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedToolCall(call);
                          }}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px] transition-colors"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-2.5 border-t border-slate-800/90 bg-[#080d17] flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <span>
            Showing <strong className="text-slate-200">{paginatedCalls.length}</strong> of{' '}
            <strong className="text-slate-200">{filteredCalls.length}</strong> tool requests
          </span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Previous
            </button>
            <span className="px-1 text-slate-300">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
