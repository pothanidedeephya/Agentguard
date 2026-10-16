/**
 * PostgreSQL Repository for Human Approvals
 */
import { dbQuery } from '../db/pool';
import { ApprovalRequest } from '../../types/agentguard';

export const approvalsRepository = {
  async create(appr: ApprovalRequest & { isDemo?: boolean }): Promise<ApprovalRequest> {
    const res = await dbQuery(
      `INSERT INTO approval_requests 
       (request_id, tool_call_id, timestamp, agent_name, server_name, tool_name, 
        input_params, risk_score, policy_reason, status, reviewer, reviewed_at, analyst_notes, is_demo)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14)
       RETURNING *`,
      [
        appr.id,
        appr.toolCallId,
        appr.timestamp,
        appr.agentName,
        appr.serverName,
        appr.toolName,
        JSON.stringify(appr.inputParams || {}),
        appr.riskScore,
        appr.policyReason,
        appr.status,
        appr.reviewer || null,
        appr.reviewedAt || null,
        appr.analystNotes || null,
        Boolean(appr.isDemo),
      ]
    );

    return mapRowToApproval(res.rows[0]);
  },

  async findAll(options: { isDemo?: boolean; status?: string } = {}): Promise<ApprovalRequest[]> {
    const conditions: string[] = [];
    const params: any[] = [];
    let idx = 1;

    if (options.isDemo !== undefined) {
      conditions.push(`is_demo = $${idx++}`);
      params.push(options.isDemo);
    }

    if (options.status && options.status !== 'ALL') {
      conditions.push(`status = $${idx++}`);
      params.push(options.status);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const res = await dbQuery(
      `SELECT * FROM approval_requests ${whereClause} ORDER BY timestamp DESC`,
      params
    );

    return res.rows.map(mapRowToApproval);
  },

  async updateDecision(
    requestId: string,
    action: 'APPROVED' | 'REJECTED',
    reviewer: string,
    notes: string
  ): Promise<ApprovalRequest | null> {
    const res = await dbQuery(
      `UPDATE approval_requests 
       SET status = $1, reviewer = $2, reviewed_at = NOW(), analyst_notes = $3
       WHERE request_id = $4
       RETURNING *`,
      [action, reviewer, notes, requestId]
    );

    if (res.rows.length === 0) return null;
    return mapRowToApproval(res.rows[0]);
  },
};

function mapRowToApproval(row: any): ApprovalRequest {
  return {
    id: row.request_id,
    toolCallId: row.tool_call_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    agentName: row.agent_name,
    serverName: row.server_name,
    toolName: row.tool_name,
    inputParams: typeof row.input_params === 'object' ? row.input_params : JSON.parse(row.input_params || '{}'),
    riskScore: row.risk_score,
    policyReason: row.policy_reason,
    status: row.status as ApprovalRequest['status'],
    reviewer: row.reviewer || undefined,
    reviewedAt: row.reviewed_at instanceof Date ? row.reviewed_at.toISOString() : (row.reviewed_at ? String(row.reviewed_at) : undefined),
    analystNotes: row.analyst_notes || undefined,
    isSimulated: Boolean(row.is_demo),
  };
}
