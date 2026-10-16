/**
 * PostgreSQL Repository for Threats
 */
import { dbQuery } from '../db/pool';
import { ThreatEvent, ThreatSeverity, ThreatCategory } from '../../types/agentguard';

export interface FindThreatsOptions {
  search?: string;
  category?: string;
  severity?: string;
  status?: string;
  isDemo?: boolean;
  limit?: number;
}

export const threatsRepository = {
  async create(threat: ThreatEvent & { isDemo?: boolean }): Promise<ThreatEvent> {
    const res = await dbQuery(
      `INSERT INTO threats
       (threat_id, timestamp, tool_call_id, threat_type, severity, risk_score, 
        source_tool, server_name, agent_name, evidence, detection_rule, status, remediation, is_demo)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING *`,
      [
        threat.id,
        threat.timestamp,
        threat.toolCallId,
        threat.category,
        threat.severity,
        threat.riskScore,
        threat.sourceTool,
        threat.serverName,
        threat.agentName,
        threat.evidence,
        threat.detectionRule,
        threat.status,
        threat.recommendedAction,
        Boolean(threat.isDemo),
      ]
    );

    return mapRowToThreat(res.rows[0]);
  },

  async findAll(options: FindThreatsOptions = {}): Promise<ThreatEvent[]> {
    const conditions: string[] = [];
    const params: any[] = [];
    let idx = 1;

    if (options.isDemo !== undefined) {
      conditions.push(`is_demo = $${idx++}`);
      params.push(options.isDemo);
    }

    if (options.category && options.category !== 'ALL') {
      conditions.push(`threat_type = $${idx++}`);
      params.push(options.category);
    }

    if (options.severity && options.severity !== 'ALL') {
      conditions.push(`severity = $${idx++}`);
      params.push(options.severity);
    }

    if (options.status && options.status !== 'ALL') {
      conditions.push(`status = $${idx++}`);
      params.push(options.status);
    }

    if (options.search && options.search.trim()) {
      conditions.push(`(
        threat_id ILIKE $${idx} OR 
        threat_type ILIKE $${idx} OR 
        source_tool ILIKE $${idx} OR 
        evidence ILIKE $${idx} OR 
        agent_name ILIKE $${idx}
      )`);
      params.push(`%${options.search.trim()}%`);
      idx++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = options.limit || 100;

    const res = await dbQuery(
      `SELECT * FROM threats ${whereClause} ORDER BY timestamp DESC LIMIT $${idx}`,
      [...params, limit]
    );

    return res.rows.map(mapRowToThreat);
  },

  async updateStatus(threatId: string, status: ThreatEvent['status']): Promise<boolean> {
    const res = await dbQuery(
      'UPDATE threats SET status = $1 WHERE threat_id = $2',
      [status, threatId]
    );
    return (res.rowCount ?? 0) > 0;
  },
};

function mapRowToThreat(row: any): ThreatEvent {
  return {
    id: row.threat_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    category: row.threat_type as ThreatCategory,
    title: getTitleForThreatType(row.threat_type),
    severity: row.severity as ThreatSeverity,
    riskScore: row.risk_score,
    sourceTool: row.source_tool,
    serverName: row.server_name,
    agentName: row.agent_name,
    toolCallId: row.tool_call_id,
    evidence: row.evidence,
    detectionRule: row.detection_rule,
    recommendedAction: row.remediation || 'Inspect agent reasoning chain and quarantine host session.',
    status: row.status as ThreatEvent['status'],
    isSimulated: Boolean(row.is_demo),
  };
}

function getTitleForThreatType(type: string): string {
  switch (type) {
    case 'PATH_TRAVERSAL':
      return 'Directory Traversal via Path Climbing Sequence';
    case 'COMMAND_INJECTION':
      return 'Arbitrary Shell Execution & System Evasion Attempt';
    case 'SECRET_LEAKAGE':
      return 'High-Entropy Secret API Key Leakage';
    case 'PROMPT_INJECTION':
      return 'Indirect Jailbreak Injection in Scraped Content';
    case 'UNAUTHORIZED_TOOL':
      return 'Unauthorized Privileged Tool Invocation Attempt';
    default:
      return `${type.replace(/_/g, ' ')} Incident`;
  }
}
