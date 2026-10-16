/**
 * AgentGuard Zod Request Validation Schemas
 * Enforces strict type-safety, boundaries, and input validation on all API endpoints
 */
import { z } from 'zod';

export const DecisionTypeEnum = z.enum(['ALLOW', 'BLOCK', 'REQUIRE_APPROVAL', 'REDACT']);
export const ThreatSeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
export const ThreatStatusEnum = z.enum(['ACTIVE', 'INVESTIGATING', 'MITIGATED', 'FALSE_POSITIVE']);
export const ServerTransportEnum = z.enum(['stdio', 'sse', 'websocket', 'http']);

// 1. Gateway Tool Evaluation & Execution
export const GatewayCallSchema = z.object({
  agentId: z.string().max(128).optional().default('agent-autonomous'),
  agentName: z.string().max(255).optional().default('Autonomous Agent'),
  serverName: z.string().min(1).max(255),
  serverId: z.string().max(64).optional(),
  toolName: z.string().min(1).max(255),
  parameters: z.record(z.string(), z.unknown()).default({}),
  authToken: z.string().optional(),
  isDemo: z.boolean().optional().default(false),
  executeDownstream: z.boolean().optional().default(true),
});

export const GatewayExecuteRequestSchema = GatewayCallSchema;

export const EvaluateRequestSchema = z.object({
  agentId: z.string().max(128).optional(),
  agentName: z.string().max(255).optional(),
  serverName: z.string().min(1).max(255),
  serverId: z.string().max(64).optional(),
  toolName: z.string().min(1).max(255),
  parameters: z.record(z.string(), z.unknown()).default({}),
  isDemo: z.boolean().optional().default(false),
});

// 2. DLP & Response Inspection
export const InspectResponseSchema = z.object({
  toolName: z.string().min(1).max(255).default('generic-tool'),
  responsePayload: z.string().min(1, 'responsePayload is required'),
  isDemo: z.boolean().optional().default(false),
});

// 3. Security Policy Upsert
export const PolicyUpsertSchema = z.object({
  id: z.string().max(64).optional(),
  name: z.string().min(1).max(255),
  description: z.string().default(''),
  enabled: z.boolean().default(true),
  ruleType: z.enum(['TOOL_RESTRICTION', 'PARAMETER_INSPECTION', 'RISK_THRESHOLD', 'RESPONSE_DLP', 'PROMPT_SAFETY']),
  targetTools: z.array(z.string()).default(['*']),
  targetServers: z.array(z.string()).default(['*']),
  riskThreshold: z.number().int().min(0).max(100).default(80),
  action: DecisionTypeEnum,
  author: z.string().max(255).optional().default('analyst@agentguard.internal'),
  configuration: z.record(z.string(), z.unknown()).optional().default({}),
});

// 4. Threat Status Update
export const ThreatStatusUpdateSchema = z.object({
  status: ThreatStatusEnum,
  remediation: z.string().max(2000).optional(),
});

// 5. Human Approval Decision
export const ApprovalDecisionSchema = z.object({
  action: z.enum(['APPROVED', 'REJECTED']),
  reviewer: z.string().max(255).optional().default('analyst@agentguard.internal'),
  analystNotes: z.string().max(2000).optional().default(''),
  resumeExecution: z.boolean().optional().default(false),
});

// 6. MCP Server Creation & Management
export const McpServerCreateSchema = z.object({
  id: z.string().min(1).max(64),
  name: z.string().min(1).max(255),
  transport: ServerTransportEnum,
  endpointOrCommand: z.string().min(1),
  status: z.enum(['CONNECTED', 'DEGRADED', 'DISCONNECTED']).default('CONNECTED'),
  tools: z.array(z.object({
    name: z.string(),
    description: z.string().default(''),
    parametersSchema: z.record(z.string(), z.unknown()).default({}),
    isAllowed: z.boolean().default(true),
    callsCount: z.number().int().default(0),
    blockedCount: z.number().int().default(0),
  })).default([]),
  configuredEnvKeys: z.array(z.string()).default([]),
  latencyMs: z.number().int().min(1).default(15),
});

export const MCPServerCreateSchema = McpServerCreateSchema;

export const McpToolAllowlistSchema = z.object({
  isAllowed: z.boolean(),
});

export const ToolAllowlistToggleSchema = McpToolAllowlistSchema;

// 7. Query Pagination & Filters
export const PaginationQuerySchema = z.object({
  search: z.string().optional(),
  limit: z.coerce.number().int().positive().max(500).default(50),
  offset: z.coerce.number().int().nonnegative().default(0),
  isDemo: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
});

export const DateRangeQuerySchema = PaginationQuerySchema.extend({
  startDate: z.string().datetime({ offset: true }).or(z.string().regex(/^\d{4}-\d{2}-\d{2}/)).optional(),
  endDate: z.string().datetime({ offset: true }).or(z.string().regex(/^\d{4}-\d{2}-\d{2}/)).optional(),
});

export const ToolCallsQuerySchema = PaginationQuerySchema.extend({
  server: z.string().optional(),
  decision: z.string().optional(),
  minRisk: z.coerce.number().optional(),
});

export const ThreatsQuerySchema = PaginationQuerySchema.extend({
  category: z.string().optional(),
  severity: z.string().optional(),
  status: z.string().optional(),
});

export const AuditLogsQuerySchema = DateRangeQuerySchema.extend({
  eventType: z.string().optional(),
});

export const ApprovalsQuerySchema = PaginationQuerySchema.extend({
  status: z.string().optional(),
});
