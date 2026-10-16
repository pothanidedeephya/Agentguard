import React, { useState, useMemo } from 'react';
import { useSecurity } from '../../context/SecurityContext';
import { DecisionBadge } from '../common/DecisionBadge';
import { RiskScoreBadge } from '../common/RiskScoreBadge';
import { Modal } from '../common/Modal';
import { AuditLog } from '../../types/agentguard';
import {
  FileText,
  Search,
  Download,
  Filter,
  Shield,
  AlertCircle,
  Database,
  ArrowUpDown,
  Lock,
} from 'lucide-react';

// Safe CSV sanitizer protecting against Spreadsheet Formula Injection
function sanitizeCsvValue(val: unknown): string {
  if (val === null || val === undefined) return '""';
  let str = String(val);

  if (/^[=\+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }

  str = str.replace(/"/g, '""');
  return `"${str}"`;
}

// Redact any confidential payload patterns
function redactSensitiveText(text: string): string {
  if (!text) return '';
  return text
    .replace(/(sk-[a-zA-Z0-9_-]{8})[a-zA-Z0-9_-]+/g, '$1...[REDACTED]')
    .replace(/(AKIA[0-9A-Z]{4})[0-9A-Z]+/g, '$1...[REDACTED]')
    .replace(/(\b\d{3}-\d{2}-\d{4}\b)/g, '***-**-****');
}

export const AuditLogsPage: React.FC = () => {
  const { auditLogs, dbState, dbHost, isBackendConnected, operatingState } = useSecurity();

  const [searchTerm, setSearchTerm] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [selectedAudit, setSelectedAudit] = useState<AuditLog | null>(null);
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const isDbActive = operatingState === 'LIVE' && isBackendConnected && dbState === 'CONNECTED';

  const filteredLogs = useMemo(() => {
    return auditLogs
      .filter((log) => {
        const matchSearch =
          log.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
          log.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
          log.reason.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (log.toolCallId && log.toolCallId.toLowerCase().includes(searchTerm.toLowerCase()));

        const matchType =
          eventTypeFilter === 'ALL' || log.eventType === eventTypeFilter;

        const matchOutcome =
          outcomeFilter === 'ALL' || log.outcome === outcomeFilter;

        return matchSearch && matchType && matchOutcome;
      })
      .sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime();
        const timeB = new Date(b.timestamp).getTime();
        return sortOrder === 'desc' ? timeB - timeA : timeA - timeB;
      });
  }, [auditLogs, searchTerm, eventTypeFilter, outcomeFilter, sortOrder]);

  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;
  const paginatedLogs = filteredLogs.slice((page - 1) * pageSize, page * pageSize);

  const handleExportCsv = () => {
    const headers = [
      'Timestamp',
      'Audit ID',
      'Request ID',
      'Actor',
      'Event Type',
      'Security Decision',
      'Risk Score',
      'Triggered Rule / Reason',
      'Execution Outcome',
    ];

    const rows = filteredLogs.map((log) => [
      log.timestamp,
      log.id,
      log.toolCallId || 'N/A',
      log.actor,
      log.eventType,
      log.decision || 'N/A',
      log.riskScore ?? 'N/A',
      redactSensitiveText(log.reason),
      log.outcome,
    ]);

    const csvContent = [
      headers.map(sanitizeCsvValue).join(','),
      ...rows.map((row) => row.map(sanitizeCsvValue).join(',')),
    ].join('\r\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `agentguard_audit_log_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="p-3.5 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 font-mono">
            <FileText size={15} className="text-cyan-400" />
            Compliance & Security Audit Trail
          </h2>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Immutable log of all MCP tool evaluations, risk scores, rule triggers, and analyst decisions
          </p>
        </div>

        <button
          onClick={handleExportCsv}
          className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors shrink-0"
        >
          <Download size={12} />
          <span>Export Audit CSV</span>
        </button>
      </div>

      {/* Storage Source Disclosure */}
      <div className="p-2.5 rounded border border-slate-800 bg-[#080d17] flex items-center justify-between gap-3 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-2">
          <Database size={13} className={isDbActive ? 'text-emerald-400' : 'text-cyan-400'} />
          <span>
            {isDbActive ? (
              <>
                <strong className="text-emerald-300">Storage Engine: PostgreSQL (Supabase)</strong> — Audit logs persist to table <code>audit_logs</code> at {dbHost || 'remote'}.
              </>
            ) : (
              <>
                <strong className="text-cyan-300">Storage Engine: Local Session Buffer</strong> — Audit logs are currently held in runtime memory (Demo Mode).
              </>
            )}
          </span>
        </div>
        <span className="text-slate-300 font-semibold shrink-0">
          Redaction Guard: Enforced
        </span>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-3 rounded-lg border border-slate-800/90 bg-[#0d1424] flex flex-wrap items-center justify-between gap-2.5 text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[260px] flex-wrap sm:flex-nowrap">
          <div className="relative flex-1 min-w-[180px]">
            <Search size={13} className="absolute left-2.5 top-2 text-slate-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Search audit ID, actor, rule, call ID..."
              className="w-full pl-8 pr-3 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 placeholder-slate-400 focus:outline-hidden focus:border-cyan-500 font-mono"
            />
          </div>

          <select
            value={eventTypeFilter}
            onChange={(e) => {
              setEventTypeFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Event Types</option>
            <option value="TOOL_EVALUATION">TOOL_EVALUATION</option>
            <option value="THREAT_DETECTED">THREAT_DETECTED</option>
            <option value="APPROVAL_DECISION">APPROVAL_DECISION</option>
            <option value="POLICY_MODIFIED">POLICY_MODIFIED</option>
            <option value="DLP_INSPECTION">DLP_INSPECTION</option>
          </select>

          <select
            value={outcomeFilter}
            onChange={(e) => {
              setOutcomeFilter(e.target.value);
              setPage(1);
            }}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Outcomes</option>
            <option value="ALLOWED">ALLOWED</option>
            <option value="BLOCKED">BLOCKED</option>
            <option value="FLAGGED">FLAGGED</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="REJECTED">REJECTED</option>
          </select>

          <button
            onClick={() => setSortOrder((s) => (s === 'desc' ? 'asc' : 'desc'))}
            className="px-2.5 py-1 bg-[#080d17] border border-slate-800 rounded text-xs text-slate-300 hover:text-white flex items-center gap-1 font-mono shrink-0"
            title="Toggle timestamp sorting"
          >
            <ArrowUpDown size={12} />
            <span>{sortOrder === 'desc' ? 'Newest First' : 'Oldest First'}</span>
          </button>
        </div>

        <span className="text-[11px] text-slate-400 font-mono">
          Showing <strong className="text-slate-200">{filteredLogs.length}</strong> records
        </span>
      </div>

      {/* Main Table: Exact Requested Columns */}
      <div className="rounded-lg border border-slate-800/90 bg-[#0d1424] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#080d17] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Request ID</th>
                <th className="py-2.5 px-3">Tool / Actor</th>
                <th className="py-2.5 px-3">Security Decision</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Triggered Rule / Reason</th>
                <th className="py-2.5 px-3">Execution Outcome</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 text-xs">
                    No audit records matching query.
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => {
                  const sanitizedReason = redactSensitiveText(log.reason);
                  const isBlocked = log.outcome === 'BLOCKED' || log.outcome === 'REJECTED';

                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedAudit(log)}
                      className="hover:bg-slate-850/50 cursor-pointer transition-colors group"
                    >
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold whitespace-nowrap group-hover:underline">
                        {log.toolCallId || log.id}
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 whitespace-nowrap">
                        <span className="font-semibold text-slate-100">{log.actor}</span>
                        <span className="text-[10px] text-slate-400 block font-mono">
                          {log.eventType}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {log.decision ? <DecisionBadge decision={log.decision} size="sm" /> : <span className="text-slate-400">—</span>}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {log.riskScore !== undefined ? (
                          <RiskScoreBadge score={log.riskScore} />
                        ) : (
                          <span className="text-slate-400">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 max-w-[280px] truncate text-slate-300">
                        {sanitizedReason}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-semibold ${
                            isBlocked ? 'text-rose-400' : 'text-emerald-400'
                          }`}
                        >
                          {log.outcome}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAudit(log);
                          }}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 text-[10px]"
                        >
                          View
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
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200"
            >
              Previous
            </button>
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

      {/* Detail Modal */}
      {selectedAudit && (
        <Modal
          isOpen={!!selectedAudit}
          onClose={() => setSelectedAudit(null)}
          title={`Audit Record: ${selectedAudit.id}`}
          subtitle={`Logged at ${new Date(selectedAudit.timestamp).toLocaleString()}`}
        >
          <div className="space-y-3 font-mono text-xs">
            <div className="grid grid-cols-2 gap-2.5 p-3 rounded border border-slate-800 bg-[#070b12]">
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Actor:</span>
                <span className="text-slate-100 font-bold">{selectedAudit.actor}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Event Type:</span>
                <span className="text-cyan-300">{selectedAudit.eventType}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Linked Request ID:</span>
                <span className="text-slate-200">{selectedAudit.toolCallId || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Execution Outcome:</span>
                <span className="text-emerald-400 font-bold">{selectedAudit.outcome}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-400 block mb-1 text-[10px] uppercase">
                Triggered Rule / Audit Justification:
              </span>
              <p className="p-3 rounded border border-slate-800 bg-slate-900/60 text-slate-200 leading-relaxed font-mono text-xs">
                {redactSensitiveText(selectedAudit.reason)}
              </p>
            </div>

            <div className="pt-2 text-[10px] text-slate-400 border-t border-slate-800/80">
              Audit Integrity: All records are tamper-resistant and recorded synchronously with policy decisions.
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
