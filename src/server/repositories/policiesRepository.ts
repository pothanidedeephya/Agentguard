/**
 * PostgreSQL Repository for Security Policies
 */
import { dbQuery } from '../db/pool';
import { PolicyRule, DecisionType } from '../../types/agentguard';

export const policiesRepository = {
  async findAll(): Promise<PolicyRule[]> {
    const res = await dbQuery('SELECT * FROM security_policies ORDER BY id ASC');
    return res.rows.map(mapRowToPolicy);
  },

  async findById(id: string): Promise<PolicyRule | null> {
    const res = await dbQuery('SELECT * FROM security_policies WHERE id = $1 LIMIT 1', [id]);
    if (res.rows.length === 0) return null;
    return mapRowToPolicy(res.rows[0]);
  },

  async upsert(policy: PolicyRule): Promise<PolicyRule> {
    const res = await dbQuery(
      `INSERT INTO security_policies 
       (id, name, description, enabled, rule_type, target_tools, target_servers, risk_threshold, action, author, configuration, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         enabled = EXCLUDED.enabled,
         rule_type = EXCLUDED.rule_type,
         target_tools = EXCLUDED.target_tools,
         target_servers = EXCLUDED.target_servers,
         risk_threshold = EXCLUDED.risk_threshold,
         action = EXCLUDED.action,
         author = EXCLUDED.author,
         configuration = EXCLUDED.configuration,
         updated_at = NOW()
       RETURNING *`,
      [
        policy.id,
        policy.name,
        policy.description,
        Boolean(policy.enabled),
        policy.ruleType,
        JSON.stringify(policy.targetTools || ['*']),
        JSON.stringify(policy.targetServers || ['*']),
        policy.riskThreshold,
        policy.action,
        policy.author || 'analyst@agentguard.internal',
        JSON.stringify(policy.configuration || {}),
      ]
    );

    return mapRowToPolicy(res.rows[0]);
  },

  async updateEnabled(id: string, enabled: boolean): Promise<boolean> {
    const res = await dbQuery(
      'UPDATE security_policies SET enabled = $1, updated_at = NOW() WHERE id = $2',
      [enabled, id]
    );
    return (res.rowCount ?? 0) > 0;
  },
};

function mapRowToPolicy(row: any): PolicyRule {
  return {
    id: row.id,
    name: row.name,
    description: row.description || '',
    enabled: Boolean(row.enabled),
    ruleType: row.rule_type as PolicyRule['ruleType'],
    targetTools: Array.isArray(row.target_tools) ? row.target_tools : (typeof row.target_tools === 'string' ? JSON.parse(row.target_tools) : ['*']),
    targetServers: Array.isArray(row.target_servers) ? row.target_servers : (typeof row.target_servers === 'string' ? JSON.parse(row.target_servers) : ['*']),
    riskThreshold: row.risk_threshold,
    action: row.action as DecisionType,
    configuration: typeof row.configuration === 'object' ? row.configuration : (row.configuration ? JSON.parse(row.configuration) : {}),
    author: row.author || 'security-team',
    lastUpdated: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
  };
}
