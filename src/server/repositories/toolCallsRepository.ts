/**
 * PostgreSQL Repository for Tool Calls
 */
import { dbQuery } from '../db/pool';
import { ToolCall, DecisionType } from '../../types/agentguard';

export interface FindToolCallsOptions {
  search?: string;
  serverName?: string;
  decision?: string;
  minRisk?: number;
  limit?: number;
  offset?: number;
  isDemo?: boolean;
}

export const toolCallsRepository = {
  async create(call: ToolCall & { isDemo?: boolean }): Promise<ToolCall> {
    const inputSummary = typeof call.inputParams === 'object' 
      ? JSON.stringify(call.inputParams).substring(0, 255) 
      : String(call.inputParams || '');
    const sanitizedInput = call.sanitizedInput || call.inputParams || {};
    const executedAt = call.status === 'EXECUTED' ? (call.executedAt || new Date().toISOString()) : null;

    const res = await dbQuery(
      `INSERT INTO tool_calls
       (call_id, timestamp, agent_id, agent_name, server_id, server_name, tool_name, 
        input_params, sanitized_input, normalized_params, input_summary, risk_score, decision, execution_status, 
        duration_ms, detection_reasons, output_data, redacted_output, audit_id, executed_at, is_demo, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15, $16::jsonb, $17::jsonb, $18::jsonb, $19, $20, $21, NOW())
       RETURNING *`,
      [
        call.id,
        call.timestamp,
        call.agentId,
        call.agentName,
        call.serverId,
        call.serverName,
        call.toolName,
        JSON.stringify(call.inputParams || {}),
        JSON.stringify(sanitizedInput),
        call.normalizedParams ? JSON.stringify(call.normalizedParams) : null,
        inputSummary,
        call.riskScore,
        call.decision,
        call.status,
        call.durationMs,
        JSON.stringify(call.detectionReasons || []),
        call.outputData ? JSON.stringify(call.outputData) : null,
        call.redactedOutput ? JSON.stringify(call.redactedOutput) : null,
        call.auditId,
        executedAt,
        Boolean(call.isDemo),
      ]
    );

    return mapRowToToolCall(res.rows[0]);
  },

  async findAll(options: FindToolCallsOptions = {}): Promise<{ calls: ToolCall[]; total: number }> {
    const conditions: string[] = [];
    const params: any[] = [];
    let idx = 1;

    if (options.isDemo !== undefined) {
      conditions.push(`is_demo = $${idx++}`);
      params.push(options.isDemo);
    }

    if (options.serverName && options.serverName !== 'ALL') {
      conditions.push(`server_name = $${idx++}`);
      params.push(options.serverName);
    }

    if (options.decision && options.decision !== 'ALL') {
      conditions.push(`decision = $${idx++}`);
      params.push(options.decision);
    }

    if (options.minRisk && options.minRisk > 0) {
      conditions.push(`risk_score >= $${idx++}`);
      params.push(options.minRisk);
    }

    if (options.search && options.search.trim()) {
      conditions.push(`(
        call_id ILIKE $${idx} OR 
        tool_name ILIKE $${idx} OR 
        agent_name ILIKE $${idx} OR 
        server_name ILIKE $${idx} OR
        input_summary ILIKE $${idx}
      )`);
      params.push(`%${options.search.trim()}%`);
      idx++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Total count
    const countRes = await dbQuery(`SELECT COUNT(*) as count FROM tool_calls ${whereClause}`, params);
    const total = parseInt(countRes.rows[0]?.count || '0', 10);

    // Paginated rows
    const limit = options.limit || 50;
    const offset = options.offset || 0;

    const dataQuery = `
      SELECT * FROM tool_calls 
      ${whereClause} 
      ORDER BY timestamp DESC 
      LIMIT $${idx++} OFFSET $${idx++}
    `;

    const dataRes = await dbQuery(dataQuery, [...params, limit, offset]);
    return {
      calls: dataRes.rows.map(mapRowToToolCall),
      total,
    };
  },

  async findById(callId: string): Promise<ToolCall | null> {
    const res = await dbQuery('SELECT * FROM tool_calls WHERE call_id = $1 LIMIT 1', [callId]);
    if (res.rows.length === 0) return null;
    return mapRowToToolCall(res.rows[0]);
  },

  async updateStatus(callId: string, status: ToolCall['status']): Promise<boolean> {
    const executedClause = status === 'EXECUTED' ? ', executed_at = NOW()' : '';
    const res = await dbQuery(
      `UPDATE tool_calls SET execution_status = $1${executedClause} WHERE call_id = $2`,
      [status, callId]
    );
    return (res.rowCount ?? 0) > 0;
  },
};

function mapRowToToolCall(row: any): ToolCall {
  return {
    id: row.call_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    agentId: row.agent_id,
    agentName: row.agent_name,
    serverName: row.server_name,
    serverId: row.server_id || 'srv-generic',
    toolName: row.tool_name,
    inputParams: typeof row.input_params === 'object' ? row.input_params : JSON.parse(row.input_params || '{}'),
    sanitizedInput: row.sanitized_input ? (typeof row.sanitized_input === 'object' ? row.sanitized_input : JSON.parse(row.sanitized_input)) : undefined,
    normalizedParams: row.normalized_params ? (typeof row.normalized_params === 'object' ? row.normalized_params : JSON.parse(row.normalized_params)) : undefined,
    riskScore: row.risk_score,
    decision: row.decision as DecisionType,
    status: row.execution_status as ToolCall['status'],
    durationMs: row.duration_ms,
    detectionReasons: Array.isArray(row.detection_reasons) ? row.detection_reasons : (typeof row.detection_reasons === 'string' ? JSON.parse(row.detection_reasons) : []),
    outputData: row.output_data ? (typeof row.output_data === 'object' ? row.output_data : JSON.parse(row.output_data)) : undefined,
    redactedOutput: row.redacted_output ? (typeof row.redacted_output === 'object' ? row.redacted_output : JSON.parse(row.redacted_output)) : undefined,
    auditId: row.audit_id || `aud-${row.id}`,
    executedAt: row.executed_at instanceof Date ? row.executed_at.toISOString() : (row.executed_at ? String(row.executed_at) : undefined),
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : (row.created_at ? String(row.created_at) : undefined),
    isSimulated: Boolean(row.is_demo),
  };
}
