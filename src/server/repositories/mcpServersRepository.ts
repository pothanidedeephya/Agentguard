/**
 * PostgreSQL Repository for MCP Servers
 */
import { dbQuery } from '../db/pool';
import { MCPServer, MCPServerTool, ServerTransport, ServerConnectionStatus } from '../../types/agentguard';

export const mcpServersRepository = {
  async findAll(): Promise<MCPServer[]> {
    const res = await dbQuery('SELECT * FROM mcp_servers ORDER BY id ASC');
    return res.rows.map(mapRowToServer);
  },

  async findById(id: string): Promise<MCPServer | null> {
    const res = await dbQuery('SELECT * FROM mcp_servers WHERE id = $1 LIMIT 1', [id]);
    if (res.rows.length === 0) return null;
    return mapRowToServer(res.rows[0]);
  },

  async updateToolAllowlist(serverId: string, toolName: string, isAllowed: boolean): Promise<boolean> {
    const server = await this.findById(serverId);
    if (!server) return false;

    const updatedTools = server.tools.map((t) =>
      t.name === toolName ? { ...t, isAllowed } : t
    );

    const res = await dbQuery(
      'UPDATE mcp_servers SET available_tools = $1::jsonb, updated_at = NOW() WHERE id = $2',
      [JSON.stringify(updatedTools), serverId]
    );

    return (res.rowCount ?? 0) > 0;
  },

  async create(server: {
    id: string;
    name: string;
    transport: ServerTransport;
    endpointOrCommand: string;
    status?: ServerConnectionStatus;
    tools?: MCPServerTool[];
    configuredEnvKeys?: string[];
    latencyMs?: number;
  }): Promise<MCPServer> {
    const res = await dbQuery(
      `INSERT INTO mcp_servers
       (id, name, transport, endpoint_or_command, connection_status, available_tools, configured_env_keys, latency_ms, created_at, updated_at, last_seen_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, NOW(), NOW(), NOW())
       RETURNING *`,
      [
        server.id,
        server.name,
        server.transport,
        server.endpointOrCommand,
        server.status || 'CONNECTED',
        JSON.stringify(server.tools || []),
        JSON.stringify(server.configuredEnvKeys || []),
        server.latencyMs || 25,
      ]
    );
    return mapRowToServer(res.rows[0]);
  },

  async recordCallMetric(serverId: string, toolName: string, isBlocked: boolean): Promise<void> {
    const server = await this.findById(serverId);
    if (!server) return;

    const updatedTools = server.tools.map((t) => {
      if (t.name === toolName) {
        return {
          ...t,
          callsCount: (t.callsCount || 0) + 1,
          blockedCount: isBlocked ? (t.blockedCount || 0) + 1 : (t.blockedCount || 0),
        };
      }
      return t;
    });

    await dbQuery(
      `UPDATE mcp_servers 
       SET allowed_calls_count = allowed_calls_count + $1,
           blocked_calls_count = blocked_calls_count + $2,
           available_tools = $3::jsonb,
           last_seen_at = NOW(),
           updated_at = NOW()
       WHERE id = $4`,
      [isBlocked ? 0 : 1, isBlocked ? 1 : 0, JSON.stringify(updatedTools), serverId]
    );
  },

  async recordPing(serverId: string, latencyMs: number): Promise<boolean> {
    const res = await dbQuery(
      'UPDATE mcp_servers SET latency_ms = $1, last_seen_at = NOW(), connection_status = $2, updated_at = NOW() WHERE id = $3',
      [latencyMs, 'CONNECTED', serverId]
    );
    return (res.rowCount ?? 0) > 0;
  },
};

function mapRowToServer(row: any): MCPServer {
  const tools: MCPServerTool[] = Array.isArray(row.available_tools)
    ? row.available_tools
    : (typeof row.available_tools === 'string' ? JSON.parse(row.available_tools) : []);

  const envKeys: string[] = Array.isArray(row.configured_env_keys)
    ? row.configured_env_keys
    : (typeof row.configured_env_keys === 'string' ? JSON.parse(row.configured_env_keys) : []);

  return {
    id: row.id,
    name: row.name,
    transport: row.transport as ServerTransport,
    endpointOrCommand: row.endpoint_or_command,
    status: row.connection_status as ServerConnectionStatus,
    lastPing: row.last_seen_at instanceof Date ? row.last_seen_at.toISOString() : String(row.last_seen_at),
    allowedCallsCount: row.allowed_calls_count || 0,
    blockedCallsCount: row.blocked_calls_count || 0,
    latencyMs: row.latency_ms || 15,
    configuredEnvKeys: envKeys,
    tools,
  };
}
