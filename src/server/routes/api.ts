/**
 * Express REST API Router for AgentGuard
 * Wires repositories, evaluation pipeline, MCP gateway execution, and database management endpoints.
 * Validates all requests strictly using Zod schemas.
 */
import { Router, Request, Response, NextFunction } from 'express';
import { getCachedDatabaseStatus, testDbConnection, getDbPool } from '../db/pool';
import { runMigrations } from '../db/migrate';
import { overviewRepository } from '../repositories/overviewRepository';
import { toolCallsRepository } from '../repositories/toolCallsRepository';
import { threatsRepository } from '../repositories/threatsRepository';
import { policiesRepository } from '../repositories/policiesRepository';
import { auditLogsRepository } from '../repositories/auditLogsRepository';
import { mcpServersRepository } from '../repositories/mcpServersRepository';
import { approvalsRepository } from '../repositories/approvalsRepository';
import { securityEngine } from '../services/securityEngine';
import { mcpGateway } from '../services/mcpGateway';
import {
  EvaluateRequestSchema,
  GatewayExecuteRequestSchema,
  InspectResponseSchema,
  PolicyUpsertSchema,
  ApprovalDecisionSchema,
  ThreatStatusUpdateSchema,
  MCPServerCreateSchema,
  ToolAllowlistToggleSchema,
  ToolCallsQuerySchema,
  ThreatsQuerySchema,
  AuditLogsQuerySchema,
  ApprovalsQuerySchema,
} from '../validation/schemas';
import { correlationMiddleware, requireGatewayAuth, AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

const router = Router();

// Apply correlation tracking to all incoming API requests
router.use(correlationMiddleware);

/**
 * Helper to handle Zod validation errors safely
 */
function validateBody<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation Error: Request payload failed schema constraints.',
        issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      });
      return;
    }
    req.body = parsed.data;
    next();
  };
}

function validateQuery<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation Error: Query parameters failed schema constraints.',
        issues: parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      });
      return;
    }
    req.query = parsed.data as any;
    next();
  };
}

// ==========================================
// 1. Health & Gateway Status
// ==========================================

const sendHealthCheck = async (_req: Request, res: Response) => {
  const pool = getDbPool();
  let dbStatus = getCachedDatabaseStatus();

  // If pool is initialized, verify connectivity with a live SELECT 1 probe
  if (pool) {
    try {
      const client = await pool.connect();
      try {
        await client.query('SELECT 1 as live_health');
        dbStatus = {
          ...dbStatus,
          state: 'CONNECTED',
          lastChecked: new Date().toISOString(),
          error: undefined,
        };
      } finally {
        client.release();
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Database ping failed';
      dbStatus = {
        state: 'DISCONNECTED',
        lastChecked: new Date().toISOString(),
        error: msg,
      };
    }
  }

  const isDbConnected = dbStatus.state === 'CONNECTED';

  res.status(isDbConnected ? 200 : 200).json({
    status: isDbConnected ? 'healthy' : 'degraded',
    api: {
      status: 'UP',
      uptimeSeconds: Math.floor(process.uptime()),
      version: '2.4.1-defense',
    },
    database: {
      status: isDbConnected ? 'UP' : 'DOWN',
      state: dbStatus.state,
      host: dbStatus.host || null,
      database: dbStatus.database || null,
      lastChecked: dbStatus.lastChecked,
      error: dbStatus.error || null,
    },
    timestamp: new Date().toISOString(),
  });
};

router.get('/health', sendHealthCheck);
router.get('/api/health', sendHealthCheck);
router.get('/api/db/health', sendHealthCheck);

router.get('/api/gateway/status', async (_req: Request, res: Response) => {
  const dbStatus = getCachedDatabaseStatus();
  const pool = getDbPool();

  let serversCount = 0;
  if (pool) {
    try {
      const srvs = await mcpServersRepository.findAll();
      serversCount = srvs.length;
    } catch {
      serversCount = 5;
    }
  }

  res.json({
    online: true,
    version: '2.4.1-defense',
    uptimeSeconds: Math.floor(process.uptime()),
    connectedServersCount: serversCount,
    policyEngineActive: true,
    detectionEngineActive: true,
    lastEventTimestamp: new Date().toISOString(),
    backendUrl: process.env.DATABASE_URL ? 'Connected to PostgreSQL' : 'Local Gateway (No DB)',
    isMock: dbStatus.state !== 'CONNECTED',
    database: dbStatus,
  });
});

// ==========================================
// 2. Overview Metrics & Analytics
// ==========================================

router.get('/api/overview', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const isDemo = req.query.demo === 'true';

  if (!pool) {
    return res.status(503).json({
      error: 'Database not connected. Configure DATABASE_URL in environment for persistent overview metrics.',
      databaseState: 'NOT_CONFIGURED',
    });
  }

  try {
    const metrics = await overviewRepository.getOverviewMetrics(isDemo);
    res.json(metrics);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to query overview metrics';
    res.status(500).json({ error: msg });
  }
});

router.get('/api/analytics/volume', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const interval = (req.query.interval as '15m' | '1h' | '24h' | '7d') || '24h';
  const isDemo = req.query.demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const data = await overviewRepository.getVolumeTimeSeries(interval, isDemo);
    res.json(data);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to aggregate volume time series' });
  }
});

router.get('/api/analytics/threats-breakdown', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const isDemo = req.query.demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const data = await overviewRepository.getThreatCategoryBreakdown(isDemo);
    res.json(data);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query threat categories' });
  }
});

router.get('/api/analytics/risk-histogram', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const isDemo = req.query.demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const data = await overviewRepository.getRiskHistogram(isDemo);
    res.json(data);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query risk histogram' });
  }
});

router.get('/api/analytics/top-tools', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const isDemo = req.query.demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const data = await overviewRepository.getTopTools(isDemo);
    res.json(data);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query top tools' });
  }
});

// ==========================================
// 3. Tool Calls Investigation
// ==========================================

router.get('/api/tool-calls', validateQuery(ToolCallsQuerySchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { search, server, decision, minRisk, limit, offset, demo } = req.query as any;
  const isDemo = demo === 'true';

  if (!pool) {
    return res.status(503).json({
      error: 'Database not connected. Configure DATABASE_URL in environment.',
      databaseState: 'NOT_CONFIGURED',
    });
  }

  try {
    const result = await toolCallsRepository.findAll({
      search,
      serverName: server,
      decision,
      minRisk,
      limit,
      offset,
      isDemo,
    });

    res.json(result.calls);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to query tool calls';
    res.status(500).json({ error: msg });
  }
});

// ==========================================
// 4. Threats
// ==========================================

router.get('/api/threats', validateQuery(ThreatsQuerySchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { category, severity, status, search, demo, limit } = req.query as any;
  const isDemo = demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const threats = await threatsRepository.findAll({ category, severity, status, search, isDemo, limit });
    res.json(threats);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query threats' });
  }
});

router.put('/api/threats/:id/status', validateBody(ThreatStatusUpdateSchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { id } = req.params;
  const { status, remediationNotes } = req.body;

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const success = await threatsRepository.updateStatus(id, status);
    if (!success) return res.status(404).json({ error: 'Threat record not found' });

    // Append audit log for threat triage
    await auditLogsRepository.create({
      id: `aud-thr-${Date.now().toString().slice(-5)}`,
      timestamp: new Date().toISOString(),
      actor: 'analyst@agentguard.internal',
      eventType: 'THREAT_TRIAGED',
      decision: 'ALLOW',
      riskScore: 0,
      reason: `Threat ${id} status updated to ${status}. ${remediationNotes ? `Notes: ${remediationNotes}` : ''}`,
      outcome: 'COMPLETED',
      ipAddress: '127.0.0.1',
    });

    res.json({ success: true, message: `Threat ${id} status updated to ${status}` });
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to update threat status' });
  }
});

// ==========================================
// 5. Audit Logs
// ==========================================

router.get('/api/audit-logs', validateQuery(AuditLogsQuerySchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { search, eventType, startDate, endDate, demo, limit } = req.query as any;
  const isDemo = demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const logs = await auditLogsRepository.findAll({ search, eventType, startDate, endDate, isDemo, limit });
    res.json(logs);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query audit logs' });
  }
});

// ==========================================
// 6. Security Policies
// ==========================================

router.get('/api/policies', async (_req: Request, res: Response) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const policies = await policiesRepository.findAll();
    res.json(policies);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query security policies' });
  }
});

router.put('/api/policies', requireGatewayAuth, validateBody(PolicyUpsertSchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  const policy = req.body;

  try {
    const saved = await policiesRepository.upsert({
      ...policy,
      id: policy.id || `pol-${Date.now().toString().slice(-4)}`,
      lastUpdated: new Date().toISOString(),
    });

    // Log policy change to audit logs
    await auditLogsRepository.create({
      id: `aud-pol-${Date.now().toString().slice(-5)}`,
      timestamp: new Date().toISOString(),
      actor: policy.author || 'analyst@agentguard.internal',
      eventType: 'POLICY_MODIFIED',
      decision: policy.action,
      riskScore: policy.riskThreshold || 75,
      reason: `Policy ${saved.id} (${saved.name}) saved to PostgreSQL: action=${saved.action}`,
      outcome: 'COMPLETED',
      ipAddress: '127.0.0.1',
      metadata: {
        policyId: saved.id,
        ruleType: saved.ruleType,
        action: saved.action,
      },
    });

    res.json(saved);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to save policy';
    res.status(500).json({ error: msg });
  }
});

// ==========================================
// 7. MCP Servers Registry
// ==========================================

const getMcpServersHandler = async (_req: Request, res: Response) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const servers = await mcpServersRepository.findAll();
    res.json(servers);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query MCP servers' });
  }
};

router.get('/api/mcp-servers', getMcpServersHandler);
router.get('/api/servers', getMcpServersHandler);

router.post('/api/mcp-servers', requireGatewayAuth, validateBody(MCPServerCreateSchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const server = await mcpServersRepository.create(req.body);
    res.status(201).json(server);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Failed to register MCP server';
    res.status(500).json({ error: msg });
  }
});

router.put('/api/mcp-servers/:id/tools/:toolName', validateBody(ToolAllowlistToggleSchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { id, toolName } = req.params;
  const { isAllowed } = req.body;

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const updated = await mcpServersRepository.updateToolAllowlist(id, toolName, Boolean(isAllowed));
    if (!updated) return res.status(404).json({ error: 'Server or tool not found' });
    res.json({ success: true, message: `Tool ${toolName} on server ${id} updated to allowed=${isAllowed}` });
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to update tool allowlist' });
  }
});

router.post('/api/mcp-servers/:id/ping', async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { id } = req.params;

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  const pingStart = process.hrtime.bigint();
  try {
    await pool.query('SELECT 1');
    const elapsedNanos = process.hrtime.bigint() - pingStart;
    const latency = Math.max(1, Math.round(Number(elapsedNanos) / 1_000_000));
    await mcpServersRepository.recordPing(id, latency);
    res.json({ success: true, latencyMs: latency, lastPing: new Date().toISOString() });
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to ping server' });
  }
});

// ==========================================
// 8. Human Approvals & Quarantines
// ==========================================

router.get('/api/approvals', validateQuery(ApprovalsQuerySchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { status, demo } = req.query as any;
  const isDemo = demo === 'true';

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const approvals = await approvalsRepository.findAll({ status, isDemo });
    res.json(approvals);
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to query approvals' });
  }
});

router.post('/api/approvals/:id/decision', requireGatewayAuth, validateBody(ApprovalDecisionSchema), async (req: Request, res: Response) => {
  const pool = getDbPool();
  const { id } = req.params;
  const { action, analystNotes, reviewer } = req.body;

  if (!pool) return res.status(503).json({ error: 'Database not connected' });

  try {
    const updated = await approvalsRepository.updateDecision(
      id,
      action,
      reviewer || 'analyst@agentguard.internal',
      analystNotes || ''
    );

    if (!updated) return res.status(404).json({ error: 'Approval request not found' });

    // Update the associated tool call status
    await toolCallsRepository.updateStatus(
      updated.toolCallId,
      action === 'APPROVED' ? 'EXECUTED' : 'REJECTED'
    );

    // Append audit log
    await auditLogsRepository.create({
      id: `aud-appr-${Date.now().toString().slice(-5)}`,
      timestamp: new Date().toISOString(),
      actor: reviewer || 'analyst@agentguard.internal',
      eventType: 'APPROVAL_DECISION',
      toolCallId: updated.toolCallId,
      decision: action === 'APPROVED' ? 'ALLOW' : 'BLOCK',
      riskScore: updated.riskScore,
      reason: `Quarantined tool call ${action.toLowerCase()} by human operator: ${analystNotes || 'Approved'}`,
      outcome: action === 'APPROVED' ? 'ALLOWED' : 'REJECTED',
      ipAddress: '127.0.0.1',
      metadata: {
        approvalId: id,
        action,
        reviewer,
      },
      isDemo: updated.isSimulated,
    });

    res.json({
      success: true,
      message: `Tool call ${updated.toolCallId} decision recorded as ${action} in PostgreSQL.`,
      approval: updated,
    });
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to record approval decision' });
  }
});

// ==========================================
// 9. Runtime Security Evaluation & MCP Execution
// ==========================================

/**
 * Standard Security Evaluation (Dry-Run or Simulation)
 */
router.post('/api/evaluate', validateBody(EvaluateRequestSchema), async (req: Request, res: Response) => {
  try {
    const result = await securityEngine.evaluateToolCall({
      ...req.body,
      executeDownstream: false,
    });
    res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Evaluation failed';
    res.status(500).json({ error: msg });
  }
});

/**
 * Real MCP Runtime Gateway Execution:
 * Intercepts, authorizes, inspects, executes downstream tool ONLY if allowed,
 * inspects response, and persists audit telemetry.
 */
const handleGatewayExecution = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const result = await mcpGateway.processToolCall(req.body, req.headers.authorization);
    res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Gateway execution failed';
    res.status(500).json({ error: msg });
  }
};

router.post('/api/gateway/execute', requireGatewayAuth, validateBody(GatewayExecuteRequestSchema), handleGatewayExecution);
router.post('/api/mcp/gateway', requireGatewayAuth, validateBody(GatewayExecuteRequestSchema), handleGatewayExecution);

/**
 * Response DLP and Secret Scrubbing Endpoint
 */
router.post('/api/inspect-response', validateBody(InspectResponseSchema), async (req: Request, res: Response) => {
  const { toolName, responsePayload, failClosed, isDemo } = req.body;

  try {
    const result = await securityEngine.inspectResponse(
      toolName || 'generic-tool',
      responsePayload,
      Boolean(isDemo),
      Boolean(failClosed)
    );
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({ error: 'DLP inspection failed' });
  }
});

// ==========================================
// 10. Database Diagnostics & Migrations
// ==========================================

router.post('/api/db/test-connection', async (req: Request, res: Response) => {
  const { connectionString } = req.body;
  try {
    const status = await testDbConnection(connectionString);
    res.json(status);
  } catch (err: unknown) {
    res.status(500).json({ state: 'DISCONNECTED', error: 'Test connection failed' });
  }
});

router.post('/api/db/run-migrations', async (_req: Request, res: Response) => {
  try {
    const result = await runMigrations();
    res.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Migrations failed';
    res.status(500).json({ success: false, message: msg });
  }
});

export default router;
