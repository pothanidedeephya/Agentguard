import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { ThreatSeverityBadge } from '../common/ThreatSeverityBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { DecisionBadge } from '../common/DecisionBadge';
import { ThreatEvent, ThreatCategory, ThreatSeverity, DecisionType } from '../../types/agentguard';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  AlertTriangle,
  FileCode,
  ShieldCheck,
  ChevronRight,
  Info,
  Terminal,
  ArrowUpRight,
  Shield,
} from 'lucide-react';

export const ThreatDetectionPage: React.FC = () => {
  const { threats, setSelectedThreat, updateThreatStatus, toolCalls, setSelectedToolCall, setCurrentPage } = useSecurity();

  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 8;

  // Map each threat to its underlying tool call to determine the final policy decision
  const threatsWithDecision = useMemo(() => {
    const callMap = new Map<string, { decision: DecisionType; status: string }>();
    toolCalls.forEach((c) => {
      callMap.set(c.id, { decision: c.decision, status: c.status });
    });

    return threats.map((t) => {
      const match = callMap.get(t.toolCallId);
      const decision: DecisionType = match?.decision || (t.severity === 'CRITICAL' ? 'BLOCK' : 'REQUIRE_APPROVAL');
      return {
        ...t,
        finalDecision: decision,
      };
    });
  }, [threats, toolCalls]);

  const filteredThreats = useMemo(() => {
    return threatsWithDecision.filter((t) => {
      const matchSearch =
        t.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.sourceTool.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.evidence.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.detectionRule.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.agentName.toLowerCase().includes(searchQuery.toLowerCase());

      const matchCategory =
        categoryFilter === 'ALL' || t.category === categoryFilter;

      const matchSeverity =
        severityFilter === 'ALL' || t.severity === severityFilter;

      const matchStatus =
        statusFilter === 'ALL' || t.status === statusFilter;

      return matchSearch && matchCategory && matchSeverity && matchStatus;
    });
  }, [threatsWithDecision, searchQuery, categoryFilter, severityFilter, statusFilter]);

  const totalPages = Math.ceil(filteredThreats.length / pageSize) || 1;
  const paginatedThreats = filteredThreats.slice((page - 1) * pageSize, page * pageSize);

  const activeCount = threats.filter((t) => t.status === 'ACTIVE').length;
  const investigatingCount = threats.filter((t) => t.status === 'INVESTIGATING').length;
  const mitigatedCount = threats.filter((t) => t.status === 'MITIGATED').length;

  return (
    <div className="space-y-4">
      {/* Header & Verification Paradigm Banner */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <ShieldAlert size={15} className="text-rose-400" />
            Threat Detection & Incident Response
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Deterministic rule-based detection engine and parameter heuristics (zero-hallucination signature analysis)
          </p>
        </div>

        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="px-2 py-0.5 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300">
            Active Incidents: {activeCount}
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-950/40 border border-amber-500/40 text-amber-300">
            Investigating: {investigatingCount}
          </span>
          <span className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-500/40 text-emerald-300">
            Mitigated: {mitigatedCount}
          </span>
        </div>
      </div>

      {/* Detection Paradigm Disclaimer */}
      <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] text-[11px] text-slate-400 flex items-center justify-between gap-3 font-mono">
        <div className="flex items-center gap-2">
          <Shield size={13} className="text-cyan-400 shrink-0" />
          <span>
            <strong className="text-slate-200">Rule-Based Detection Engine: </strong>
            Violations are verified using deterministic path traversal sanitization, shell token analysis, DLP regex, and MCP protocol constraints.
          </span>
        </div>
        <span className="text-emerald-400 font-semibold shrink-0">Deterministic v2.4</span>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-wrap items-center justify-between gap-2.5 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px] flex-wrap sm:flex-nowrap">
          <div className="relative flex-1 min-w-[180px]">
            <Search size={13} className="absolute left-2.5 top-2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder="Search threat title, rule, evidence snippet, tool..."
              className="w-full pl-8 pr-3 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => {
              setCategoryFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Categories</option>
            <option value="PATH_TRAVERSAL">Path Traversal</option>
            <option value="COMMAND_INJECTION">Command Injection</option>
            <option value="SECRET_LEAKAGE">Secret Leakage</option>
            <option value="PROMPT_INJECTION">Prompt Injection</option>
            <option value="UNAUTHORIZED_TOOL">Unauthorized Tool</option>
            <option value="SUSPICIOUS_PAYLOAD">Suspicious Payload</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Statuses</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="MITIGATED">MITIGATED</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
          </select>
        </div>

        <span className="text-[11px] font-mono text-slate-400">
          Showing <strong className="text-slate-200">{filteredThreats.length}</strong> alerts
        </span>
      </div>

      {/* Main Threat Analysis Table */}
      <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#080d17] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Threat ID & Title</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Triggered Rule</th>
                <th className="py-2.5 px-3">Detected Pattern / Evidence</th>
                <th className="py-2.5 px-3">Policy Decision</th>
                <th className="py-2.5 px-3">Recommended Response</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {paginatedThreats.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400 text-xs">
                    No threat alerts matching current filter parameters.
                  </td>
                </tr>
              ) : (
                paginatedThreats.map((threat) => (
                  <tr
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className="hover:bg-slate-850/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <ThreatSeverityBadge severity={threat.severity} />
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="text-cyan-400 font-bold group-hover:underline">
                        {threat.id}
                      </div>
                      <div className="text-slate-200 font-sans text-xs font-medium truncate max-w-[180px]">
                        {threat.title}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px]">
                        {threat.category}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <RiskScoreBadge score={threat.riskScore} />
                    </td>
                    <td className="py-2.5 px-3 text-emerald-400 whitespace-nowrap font-mono text-[10px]">
                      {threat.detectionRule}
                    </td>
                    <td className="py-2.5 px-3 max-w-[220px] truncate text-slate-300">
                      {threat.evidence}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <DecisionBadge decision={threat.finalDecision} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 max-w-[200px] truncate text-slate-400 text-[10px] font-sans">
                      {threat.recommendedAction}
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedThreat(threat);
                        }}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px] transition-colors"
                      >
                        Triage
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-2.5 border-t border-slate-800/90 bg-[#080d17] flex items-center justify-between text-[11px] text-slate-400 font-mono">
          <span>
            Showing {paginatedThreats.length} of {filteredThreats.length} threat incidents
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
