/**
 * PostgreSQL Repository for Audit Logs
 */
import { dbQuery } from '../db/pool';
import { AuditLog, DecisionType } from '../../types/agentguard';

export interface FindAuditLogsOptions {
  search?: string;
  eventType?: string;
  startDate?: string;
  endDate?: string;
  isDemo?: boolean;
  limit?: number;
}

export const auditLogsRepository = {
  async create(log: AuditLog & { isDemo?: boolean }): Promise<AuditLog> {
    const res = await dbQuery(
      `INSERT INTO audit_logs 
       (audit_id, timestamp, actor, event_type, tool_call_id, decision, risk_score, reason, outcome, ip_address, metadata, is_demo)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)
       RETURNING *`,
      [
        log.id,
        log.timestamp,
        log.actor,
        log.eventType,
        log.toolCallId || null,
        log.decision || null,
        log.riskScore ?? null,
        log.reason,
        log.outcome,
        log.ipAddress || '127.0.0.1',
        JSON.stringify(log.metadata || {}),
        Boolean(log.isDemo),
      ]
    );

    return mapRowToAuditLog(res.rows[0]);
  },

  async findAll(options: FindAuditLogsOptions = {}): Promise<AuditLog[]> {
    const conditions: string[] = [];
    const params: any[] = [];
    let idx = 1;

    if (options.isDemo !== undefined) {
      conditions.push(`is_demo = $${idx++}`);
      params.push(options.isDemo);
    }

    if (options.eventType && options.eventType !== 'ALL') {
      conditions.push(`event_type = $${idx++}`);
      params.push(options.eventType);
    }

    if (options.startDate) {
      conditions.push(`timestamp >= $${idx++}`);
      params.push(options.startDate);
    }

    if (options.endDate) {
      conditions.push(`timestamp <= $${idx++}`);
      params.push(options.endDate);
    }

    if (options.search && options.search.trim()) {
      conditions.push(`(
        audit_id ILIKE $${idx} OR 
        actor ILIKE $${idx} OR 
        reason ILIKE $${idx} OR 
        tool_call_id ILIKE $${idx}
      )`);
      params.push(`%${options.search.trim()}%`);
      idx++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = options.limit || 100;

    const res = await dbQuery(
      `SELECT * FROM audit_logs ${whereClause} ORDER BY timestamp DESC LIMIT $${idx}`,
      [...params, limit]
    );

    return res.rows.map(mapRowToAuditLog);
  },
};

function mapRowToAuditLog(row: any): AuditLog {
  return {
    id: row.audit_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    actor: row.actor,
    eventType: row.event_type as AuditLog['eventType'],
    toolCallId: row.tool_call_id || undefined,
    decision: row.decision as DecisionType | undefined,
    riskScore: row.risk_score ?? undefined,
    reason: row.reason,
    outcome: row.outcome as AuditLog['outcome'],
    ipAddress: row.ip_address,
    metadata: typeof row.metadata === 'object' ? row.metadata : (row.metadata ? JSON.parse(row.metadata) : {}),
  };
}
