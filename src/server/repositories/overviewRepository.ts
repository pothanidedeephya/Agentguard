/**
 * PostgreSQL Repository for Real-Time Analytics & Overview Dashboard Aggregations
 */
import { dbQuery } from '../db/pool';
import { OverviewMetrics } from '../../types/agentguard';

export const overviewRepository = {
  async getOverviewMetrics(isDemo = false): Promise<OverviewMetrics> {
    const query = `
      SELECT 
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE decision = 'ALLOW')::int AS allowed,
        COUNT(*) FILTER (WHERE decision = 'BLOCK')::int AS blocked,
        COUNT(*) FILTER (WHERE decision = 'REQUIRE_APPROVAL')::int AS approvals,
        COUNT(*) FILTER (WHERE decision = 'REDACT')::int AS redactions
      FROM tool_calls
      WHERE is_demo = $1
    `;
    const toolCallsRes = await dbQuery(query, [isDemo]);
    const row = toolCallsRes.rows[0] || {};

    const threatsQuery = `
      SELECT COUNT(*)::int AS active_threats
      FROM threats
      WHERE is_demo = $1 AND status = 'ACTIVE'
    `;
    const threatsRes = await dbQuery(threatsQuery, [isDemo]);
    const activeThreats = threatsRes.rows[0]?.active_threats || 0;

    // Delta trends: compare last 24h with previous 24h
    const trendQuery = `
      SELECT 
        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours')::int AS current_24h,
        COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '48 hours' AND timestamp < NOW() - INTERVAL '24 hours')::int AS prev_24h,
        COUNT(*) FILTER (WHERE decision = 'BLOCK' AND timestamp >= NOW() - INTERVAL '24 hours')::int AS current_blocked,
        COUNT(*) FILTER (WHERE decision = 'BLOCK' AND timestamp >= NOW() - INTERVAL '48 hours' AND timestamp < NOW() - INTERVAL '24 hours')::int AS prev_blocked
      FROM tool_calls
      WHERE is_demo = $1
    `;
    const trendRes = await dbQuery(trendQuery, [isDemo]);
    const tRow = trendRes.rows[0] || {};

    const currTotal = tRow.current_24h || 0;
    const prevTotal = tRow.prev_24h || 0;
    const deltaTotal = prevTotal > 0 ? parseFloat((((currTotal - prevTotal) / prevTotal) * 100).toFixed(1)) : 0;

    const currBlocked = tRow.current_blocked || 0;
    const prevBlocked = tRow.prev_blocked || 0;
    const deltaBlocked = prevBlocked > 0 ? parseFloat((((currBlocked - prevBlocked) / prevBlocked) * 100).toFixed(1)) : 0;

    return {
      totalToolCalls: row.total || 0,
      allowedCalls: row.allowed || 0,
      blockedCalls: row.blocked || 0,
      approvalRequiredCalls: row.approvals || 0,
      redactionsCount: row.redactions || 0,
      activeThreatsCount: activeThreats,
      trends: {
        totalCallsDeltaPct: deltaTotal,
        blockedDeltaPct: deltaBlocked,
        threatsDeltaPct: 0,
      },
    };
  },

  async getVolumeTimeSeries(interval: '15m' | '1h' | '24h' | '7d', isDemo = false) {
    let dateInterval = "INTERVAL '24 hours'";
    let timeFormat = "HH24:00";
    let bucket = "date_trunc('hour', timestamp)";

    if (interval === '15m') {
      dateInterval = "INTERVAL '1 hour'";
      timeFormat = "HH24:MI";
      bucket = "date_trunc('minute', timestamp)";
    } else if (interval === '1h') {
      dateInterval = "INTERVAL '6 hours'";
      timeFormat = "HH24:MI";
      bucket = "date_trunc('hour', timestamp)";
    } else if (interval === '7d') {
      dateInterval = "INTERVAL '7 days'";
      timeFormat = "Dy";
      bucket = "date_trunc('day', timestamp)";
    }

    const query = `
      SELECT 
        to_char(${bucket}, '${timeFormat}') AS time_label,
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE decision = 'ALLOW')::int AS allowed,
        COUNT(*) FILTER (WHERE decision = 'BLOCK')::int AS blocked,
        COUNT(*) FILTER (WHERE decision = 'REQUIRE_APPROVAL')::int AS approval
      FROM tool_calls
      WHERE is_demo = $1 AND timestamp >= NOW() - ${dateInterval}
      GROUP BY ${bucket}, time_label
      ORDER BY ${bucket} ASC
    `;

    const res = await dbQuery(query, [isDemo]);
    return res.rows.map((r) => ({
      time: r.time_label,
      total: r.total,
      allowed: r.allowed,
      blocked: r.blocked,
      approval: r.approval,
    }));
  },

  async getThreatCategoryBreakdown(isDemo = false) {
    const query = `
      SELECT threat_type AS name, COUNT(*)::int AS count
      FROM threats
      WHERE is_demo = $1
      GROUP BY threat_type
      ORDER BY count DESC
    `;
    const res = await dbQuery(query, [isDemo]);

    const colors: Record<string, string> = {
      PATH_TRAVERSAL: '#f43f5e',
      COMMAND_INJECTION: '#fb923c',
      SECRET_LEAKAGE: '#c084fc',
      PROMPT_INJECTION: '#38bdf8',
      UNAUTHORIZED_TOOL: '#facc15',
      SUSPICIOUS_PAYLOAD: '#a855f7',
    };

    return res.rows.map((r) => ({
      name: r.name.replace(/_/g, ' '),
      category: r.name,
      count: r.count,
      color: colors[r.name] || '#94a3b8',
    }));
  },

  async getRiskHistogram(isDemo = false) {
    const query = `
      SELECT 
        COUNT(*) FILTER (WHERE risk_score BETWEEN 0 AND 19)::int AS safe,
        COUNT(*) FILTER (WHERE risk_score BETWEEN 20 AND 39)::int AS low,
        COUNT(*) FILTER (WHERE risk_score BETWEEN 40 AND 59)::int AS med,
        COUNT(*) FILTER (WHERE risk_score BETWEEN 60 AND 79)::int AS elevated,
        COUNT(*) FILTER (WHERE risk_score BETWEEN 80 AND 100)::int AS critical
      FROM tool_calls
      WHERE is_demo = $1
    `;
    const res = await dbQuery(query, [isDemo]);
    const r = res.rows[0] || {};

    return [
      { range: '0 - 19 (Safe)', count: r.safe || 0 },
      { range: '20 - 39 (Low)', count: r.low || 0 },
      { range: '40 - 59 (Med)', count: r.med || 0 },
      { range: '60 - 79 (Elevated)', count: r.elevated || 0 },
      { range: '80 - 100 (Critical)', count: r.critical || 0 },
    ];
  },

  async getTopTools(isDemo = false) {
    const invokedQuery = `
      SELECT tool_name AS tool, COUNT(*)::int AS calls
      FROM tool_calls
      WHERE is_demo = $1
      GROUP BY tool_name
      ORDER BY calls DESC
      LIMIT 5
    `;
    const blockedQuery = `
      SELECT tool_name AS tool, COUNT(*)::int AS blocks
      FROM tool_calls
      WHERE is_demo = $1 AND decision = 'BLOCK'
      GROUP BY tool_name
      ORDER BY blocks DESC
      LIMIT 5
    `;

    const [invokedRes, blockedRes] = await Promise.all([
      dbQuery(invokedQuery, [isDemo]),
      dbQuery(blockedQuery, [isDemo]),
    ]);

    return {
      topInvoked: invokedRes.rows,
      topBlocked: blockedRes.rows,
    };
  },
};
