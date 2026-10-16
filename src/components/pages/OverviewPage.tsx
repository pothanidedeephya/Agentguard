import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { DecisionBadge } from '../common/DecisionBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { ThreatSeverityBadge } from '../common/ThreatSeverityBadge';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  Activity,
  Server,
  Terminal,
  RotateCcw,
  Search,
  Filter,
  CheckCircle2,
  TrendingUp,
  ArrowUpRight,
  Wifi,
  WifiOff,
  AlertTriangle,
  FileText,
  Radio,
  ExternalLink,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { DecisionType, ToolCall, ThreatEvent } from '../../types/agentguard';

export const OverviewPage: React.FC = () => {
  const {
    metrics,
    gatewayStatus,
    isBackendConnected,
    isDemoMode,
    operatingState,
    dbState,
    dbHost,
    dbError,
    toolCalls,
    threats,
    mcpServers,
    auditLogs,
    checkBackendConnection,
    isCheckingConnection,
    setSelectedToolCall,
    setSelectedThreat,
    setCurrentPage,
  } = useSecurity();

  const [tableSearch, setTableSearch] = useState('');
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 6;

  const isLiveActive = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  // High-risk events count (score >= 70 or ACTIVE status)
  const highRiskEventsCount = useMemo(() => {
    return threats.filter((t) => t.riskScore >= 70 || t.status === 'ACTIVE').length;
  }, [threats]);

  // Filtered recent tool calls
  const filteredCalls = useMemo(() => {
    return toolCalls.filter((call) => {
      const matchesSearch =
        call.toolName.toLowerCase().includes(tableSearch.toLowerCase()) ||
        call.agentName.toLowerCase().includes(tableSearch.toLowerCase()) ||
        call.serverName.toLowerCase().includes(tableSearch.toLowerCase()) ||
        call.id.toLowerCase().includes(tableSearch.toLowerCase());

      const matchesDecision =
        decisionFilter === 'ALL' || call.decision === decisionFilter;

      return matchesSearch && matchesDecision;
    });
  }, [toolCalls, tableSearch, decisionFilter]);

  const paginatedCalls = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredCalls.slice(start, start + pageSize);
  }, [filteredCalls, page]);

  const totalPages = Math.ceil(filteredCalls.length / pageSize) || 1;

  // Real Risk Score Distribution (calculated dynamically from current toolCalls)
  const dynamicRiskDistribution = useMemo(() => {
    const buckets = [
      { range: '0-19', count: 0, label: 'Safe', color: '#10b981' },
      { range: '20-39', count: 0, label: 'Low', color: '#38bdf8' },
      { range: '40-59', count: 0, label: 'Med', color: '#eab308' },
      { range: '60-79', count: 0, label: 'Elevated', color: '#f97316' },
      { range: '80-100', count: 0, label: 'Critical', color: '#ef4444' },
    ];

    if (toolCalls.length === 0) {
      return buckets;
    }

    toolCalls.forEach((call) => {
      const s = call.riskScore;
      if (s < 20) buckets[0].count++;
      else if (s < 40) buckets[1].count++;
      else if (s < 60) buckets[2].count++;
      else if (s < 80) buckets[3].count++;
      else buckets[4].count++;
    });

    return buckets;
  }, [toolCalls]);

  // Real Threat Categories Breakdown (calculated from real threats data)
  const dynamicThreatCategories = useMemo(() => {
    const counts: Record<string, number> = {};
    const palette = ['#f43f5e', '#fb923c', '#c084fc', '#38bdf8', '#facc15', '#a855f7'];

    threats.forEach((t) => {
      const key = t.category.replace(/_/g, ' ');
      counts[key] = (counts[key] || 0) + 1;
    });

    const entries = Object.entries(counts).map(([name, value], idx) => ({
      name,
      value,
      color: palette[idx % palette.length],
    }));

    if (entries.length === 0) {
      return [{ name: 'Zero Threats', value: 1, color: '#10b981' }];
    }

    return entries;
  }, [threats]);

  // Recent 4 Audit Logs for Overview
  const recentAuditActivity = useMemo(() => {
    return auditLogs.slice(0, 4);
  }, [auditLogs]);

  // Recent 4 Security Threats for Overview
  const recentSecurityThreats = useMemo(() => {
    return threats.slice(0, 4);
  }, [threats]);

  return (
    <div className="space-y-4">
      {/* Operating Environment Banner: Truth in State */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-lg border border-slate-800 bg-[#080d17] text-xs">
        <div className="flex items-center gap-2.5">
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              isLiveActive
                ? 'bg-emerald-400'
                : isDemoMode
                ? 'bg-cyan-400'
                : 'bg-amber-400'
            }`}
          />
          <div>
            <span className="font-semibold text-slate-100">
              {isLiveActive ? 'Live Security Feed' : isDemoMode ? 'Demo Data Mode' : 'Database Offline'}
            </span>
            <span className="text-slate-400 ml-2">
              {isLiveActive
                ? `Active PostgreSQL records streamed from ${dbHost || 'Supabase'}`
                : isDemoMode
                ? 'Displaying synthetic SOC telemetry for demonstration. Real database state is not connected.'
                : dbError || 'PostgreSQL database unreachable. Running in disconnected safety mode.'}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => checkBackendConnection()}
            disabled={isCheckingConnection}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-mono transition-colors"
            title="Poll backend health & sync database state"
          >
            <RotateCcw size={11} className={isCheckingConnection ? 'animate-spin' : ''} />
            <span>Sync DB</span>
          </button>
          {!isLiveActive && (
            <button
              onClick={() => setCurrentPage('settings')}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[11px] font-mono transition-colors"
            >
              Configure DB
            </button>
          )}
        </div>
      </div>

      {/* Row of 5 Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
        {/* Metric 1: Total Tool Requests */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Total Requests</span>
            <Terminal size={14} className="text-slate-400" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-100 tabular-nums">
            {metrics.totalToolCalls.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Intercepted MCP calls
          </div>
        </div>

        {/* Metric 2: Allowed Requests */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Allowed</span>
            <ShieldCheck size={14} className="text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 tabular-nums">
            {metrics.allowedCalls.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            {((metrics.allowedCalls / (metrics.totalToolCalls || 1)) * 100).toFixed(1)}% verified safe
          </div>
        </div>

        {/* Metric 3: Blocked Requests */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Blocked</span>
            <ShieldAlert size={14} className="text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 tabular-nums">
            {metrics.blockedCalls.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Quarantined violations
          </div>
        </div>

        {/* Metric 4: Requests Awaiting Approval */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Awaiting Approval</span>
            <Clock size={14} className="text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 tabular-nums">
            {metrics.approvalRequiredCalls.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            HITL authorization
          </div>
        </div>

        {/* Metric 5: Current High-Risk Events */}
        <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] space-y-1.5 col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>High-Risk Events</span>
            <AlertTriangle size={14} className="text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 tabular-nums">
            {highRiskEventsCount}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Risk score &ge; 70 or active
          </div>
        </div>
      </div>

      {/* Main Grid: Left Column (Table & Threat Feed) vs Right Column (Analytics & MCP Status) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: 7 Cols */}
        <div className="lg:col-span-7 space-y-4">
          {/* Tool Requests Table */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] overflow-hidden">
            {/* Table Toolbar */}
            <div className="p-3.5 border-b border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                  Recent Tool Requests
                </h3>
                <p className="text-[11px] text-slate-400">
                  Real-time MCP execution interception log
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <div className="relative">
                  <Search size={12} className="absolute left-2.5 top-2 text-slate-400" />
                  <input
                    type="text"
                    value={tableSearch}
                    onChange={(e) => {
                      setTableSearch(e.target.value);
                      setPage(1);
                    }}
                    placeholder="Filter tool, agent..."
                    className="pl-7 pr-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-[11px] text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500 font-mono w-36 sm:w-44"
                  />
                </div>

                <div className="flex items-center p-0.5 bg-slate-900 rounded border border-slate-800 text-[10px] font-mono">
                  {(['ALL', 'ALLOW', 'BLOCK', 'REQUIRE_APPROVAL'] as const).map((dec) => (
                    <button
                      key={dec}
                      onClick={() => {
                        setDecisionFilter(dec);
                        setPage(1);
                      }}
                      className={`px-2 py-0.5 rounded transition-colors ${
                        decisionFilter === dec
                          ? 'bg-slate-800 text-cyan-300 font-semibold'
                          : 'text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {dec === 'REQUIRE_APPROVAL' ? 'APPROVAL' : dec}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Dense Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-[#080d17] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-2 px-3">Timestamp</th>
                    <th className="py-2 px-3">Request ID</th>
                    <th className="py-2 px-3">Tool Name</th>
                    <th className="py-2 px-3">Operation / Server</th>
                    <th className="py-2 px-3">Risk</th>
                    <th className="py-2 px-3">Decision</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3 text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {paginatedCalls.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-slate-400 text-xs">
                        No tool requests matching filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedCalls.map((call) => (
                      <tr
                        key={call.id}
                        onClick={() => setSelectedToolCall(call)}
                        className="hover:bg-slate-850/50 cursor-pointer transition-colors group"
                      >
                        <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                          {new Date(call.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2 px-3 text-cyan-400 font-bold whitespace-nowrap group-hover:underline">
                          {call.id}
                        </td>
                        <td className="py-2 px-3 text-slate-100 font-semibold whitespace-nowrap">
                          {call.toolName}
                        </td>
                        <td className="py-2 px-3 text-slate-400 whitespace-nowrap">
                          {call.serverName}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <RiskScoreBadge score={call.riskScore} showLabel={false} />
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <DecisionBadge decision={call.decision} size="sm" />
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span
                            className={`text-[10px] font-semibold ${
                              call.status === 'BLOCKED'
                                ? 'text-rose-400'
                                : call.status === 'PENDING_APPROVAL'
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {call.status}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedToolCall(call);
                            }}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 underline font-mono"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="p-2.5 border-t border-slate-800/90 bg-[#080d17] flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>
                Showing {paginatedCalls.length} of {filteredCalls.length} requests
              </span>
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
                >
                  Prev
                </button>
                <span className="px-1 text-slate-300">
                  {page} / {totalPages}
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

          {/* Recent Security Events */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] p-3.5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-2.5">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                  <ShieldAlert size={14} className="text-rose-400" />
                  Recent Security Events
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Automated threat signatures triggered by agent tool calls
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('threats')}
                className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
              >
                <span>All Threats ({threats.length})</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="space-y-2">
              {recentSecurityThreats.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-400 font-mono">
                  No active security threats logged.
                </div>
              ) : (
                recentSecurityThreats.map((threat) => (
                  <div
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className="p-2.5 rounded border border-slate-800 bg-[#080d17] hover:border-slate-700 cursor-pointer transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <div className="flex items-center gap-2 flex-wrap">
                        <ThreatSeverityBadge severity={threat.severity} />
                        <span className="text-cyan-400 font-semibold">{threat.id}</span>
                        <span className="text-slate-200 font-semibold">{threat.title}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <RiskScoreBadge score={threat.riskScore} showLabel={false} />
                        <span className="text-slate-400">{new Date(threat.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 bg-slate-900/60 px-2 py-1 rounded border border-slate-800 truncate">
                      <span className="text-cyan-400 mr-1.5">Rule:</span>
                      <span>{threat.detectionRule}</span>
                      <span className="mx-2 text-slate-600">|</span>
                      <span className="text-slate-300">Evidence: {threat.evidence}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column: 5 Cols */}
        <div className="lg:col-span-5 space-y-4">
          {/* Risk Score Distribution Chart */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] p-3.5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-2">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                  Risk Score Distribution
                </h3>
                <p className="text-[11px] text-slate-400">
                  Computed threat severity (0 - 100)
                </p>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                Evaluations: {toolCalls.length}
              </span>
            </div>

            <div className="h-36 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dynamicRiskDistribution}>
                  <XAxis dataKey="range" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#080d17',
                      border: '1px solid #1e293b',
                      borderRadius: '6px',
                      fontSize: '11px',
                      fontFamily: 'monospace',
                    }}
                  />
                  <Bar dataKey="count" fill="#38bdf8" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-5 gap-1 text-center font-mono text-[10px] pt-1 border-t border-slate-800/80">
              {dynamicRiskDistribution.map((b, i) => (
                <div key={i} className="text-slate-400">
                  <div className="font-semibold text-slate-200">{b.count}</div>
                  <div style={{ color: b.color }}>{b.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Categories Chart */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] p-3.5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-2">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                  Threat Categories Breakdown
                </h3>
                <p className="text-[11px] text-slate-400">
                  Distribution of detected attack vectors
                </p>
              </div>
              <span className="text-[10px] font-mono text-slate-400">
                {threats.length} Total Alerts
              </span>
            </div>

            <div className="h-32 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={dynamicThreatCategories}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={36}
                    outerRadius={56}
                    paddingAngle={3}
                  >
                    {dynamicThreatCategories.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#080d17',
                      border: '1px solid #1e293b',
                      borderRadius: '6px',
                      fontSize: '11px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="space-y-1 font-mono text-[11px]">
              {dynamicThreatCategories.map((item, idx) => (
                <div key={idx} className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-1.5 truncate">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="truncate">{item.name}</span>
                  </span>
                  <span className="text-slate-400 font-semibold shrink-0">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* MCP Connection Status */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] p-3.5 space-y-2.5">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-2">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                  <Server size={14} className="text-cyan-400" />
                  MCP Connection Status
                </h3>
                <p className="text-[11px] text-slate-400">
                  Active Model Context Protocol daemon transports
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('mcp-servers')}
                className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
              >
                <span>Manage</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="space-y-2">
              {mcpServers.map((server) => (
                <div
                  key={server.id}
                  className="p-2.5 rounded border border-slate-800 bg-[#080d17] flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          server.status === 'CONNECTED' ? 'bg-emerald-400' : 'bg-amber-400'
                        }`}
                      />
                      <span className="font-semibold text-slate-100 font-mono truncate">
                        {server.name}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400 uppercase">
                        [{server.transport}]
                      </span>
                    </div>
                    <div className="text-[10px] font-mono text-slate-400 truncate">
                      {server.endpointOrCommand}
                    </div>
                  </div>

                  <div className="text-right text-[11px] font-mono shrink-0 ml-2">
                    <div className="text-cyan-300 font-semibold">{server.tools.length} Tools</div>
                    <div className="text-slate-400 text-[10px]">{server.latencyMs}ms latency</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Audit Activity */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] p-3.5 space-y-2.5">
            <div className="flex items-center justify-between border-b border-slate-800/90 pb-2">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono flex items-center gap-2">
                  <FileText size={14} className="text-slate-400" />
                  Audit Activity
                </h3>
                <p className="text-[11px] text-slate-400">
                  Immutable security operations log
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('audit-logs')}
                className="text-[11px] font-mono text-cyan-400 hover:underline flex items-center gap-1"
              >
                <span>Audit Trail</span>
                <ArrowUpRight size={12} />
              </button>
            </div>

            <div className="space-y-1.5">
              {recentAuditActivity.map((log) => (
                <div
                  key={log.id}
                  className="p-2 rounded border border-slate-800/80 bg-[#080d17] text-[11px] font-mono space-y-0.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-slate-200 font-semibold">{log.eventType}</span>
                    <span className="text-slate-400 text-[10px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-slate-400 truncate">
                    Actor: <span className="text-slate-300">{log.actor}</span> · Outcome:{' '}
                    <span
                      className={
                        log.outcome === 'BLOCKED' || log.outcome === 'REJECTED'
                          ? 'text-rose-400 font-bold'
                          : 'text-emerald-400'
                      }
                    >
                      {log.outcome}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
