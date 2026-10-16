/**
 * AgentGuard - Core Type Definitions
 * Runtime Defence for MCP-Connected AI Tools
 */

export type DecisionType = 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REDACT';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ThreatCategory = 
  | 'PATH_TRAVERSAL'
  | 'UNAUTHORIZED_TOOL'
  | 'COMMAND_INJECTION'
  | 'SECRET_LEAKAGE'
  | 'PROMPT_INJECTION'
  | 'SUSPICIOUS_PAYLOAD'
  | 'RATE_LIMIT_ANOMALY';

export type ServerTransport = 'stdio' | 'sse' | 'websocket' | 'http';

export type ServerConnectionStatus = 'CONNECTED' | 'DEGRADED' | 'DISCONNECTED';

export interface ToolCall {
  id: string;
  timestamp: string;
  agentId: string;
  agentName: string;
  serverName: string;
  serverId: string;
  toolName: string;
  inputParams: Record<string, unknown>;
  sanitizedInput?: Record<string, unknown>;
  normalizedParams?: Record<string, unknown>;
  riskScore: number; // 0 - 100
  decision: DecisionType;
  status: 'EXECUTED' | 'BLOCKED' | 'FLAGGED_POST_EXEC' | 'PENDING_APPROVAL' | 'REJECTED';
  durationMs: number;
  detectionReasons: string[];
  outputData?: unknown;
  redactedOutput?: unknown;
  auditId: string;
  executedAt?: string;
  createdAt?: string;
  isSimulated?: boolean;
}

export interface ThreatEvent {
  id: string;
  timestamp: string;
  category: ThreatCategory;
  title: string;
  severity: ThreatSeverity;
  riskScore: number;
  sourceTool: string;
  serverName: string;
  agentName: string;
  toolCallId: string;
  evidence: string;
  detectionRule: string;
  recommendedAction: string;
  status: 'ACTIVE' | 'INVESTIGATING' | 'MITIGATED' | 'FALSE_POSITIVE';
  isSimulated?: boolean;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  ruleType: 'TOOL_RESTRICTION' | 'PARAMETER_INSPECTION' | 'RISK_THRESHOLD' | 'RESPONSE_DLP' | 'PROMPT_SAFETY';
  targetTools: string[]; // e.g. ["*"] or ["filesystem/read_file", "shell/exec"]
  targetServers: string[]; // e.g. ["*"] or ["filesystem-mcp"]
  riskThreshold: number; // triggers action if risk >= this score
  action: DecisionType;
  enabled: boolean;
  configuration?: Record<string, unknown>;
  lastUpdated: string;
  author: string;
}

export interface MCPServerTool {
  name: string;
  description: string;
  parametersSchema: Record<string, unknown>;
  isAllowed: boolean;
  callsCount: number;
  blockedCount: number;
}

export interface MCPServer {
  id: string;
  name: string;
  transport: ServerTransport;
  endpointOrCommand: string;
  status: ServerConnectionStatus;
  tools: MCPServerTool[];
  lastPing: string;
  allowedCallsCount: number;
  blockedCallsCount: number;
  configuredEnvKeys: string[];
  latencyMs: number;
  updatedAt?: string;
  createdAt?: string;
}

export interface ApprovalRequest {
  id: string;
  toolCallId: string;
  timestamp: string;
  agentName: string;
  serverName: string;
  toolName: string;
  inputParams: Record<string, unknown>;
  riskScore: number;
  policyReason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  reviewer?: string;
  reviewedAt?: string;
  analystNotes?: string;
  isSimulated?: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  eventType: 'TOOL_EVALUATION' | 'THREAT_DETECTED' | 'POLICY_MODIFIED' | 'APPROVAL_DECISION' | 'DLP_INSPECTION' | 'GATEWAY_ALERT' | 'THREAT_TRIAGED';
  toolCallId?: string;
  decision?: DecisionType;
  riskScore?: number;
  reason: string;
  outcome: 'ALLOWED' | 'BLOCKED' | 'FLAGGED' | 'COMPLETED' | 'REJECTED';
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}

export interface InspectionFinding {
  type: 'API_KEY' | 'PII_SSN' | 'PII_EMAIL' | 'PII_PHONE' | 'PROMPT_INJECTION' | 'CREDENTIAL' | 'MALICIOUS_INSTRUCTION';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  matchSnippet: string;
  position: { start: number; end: number };
  explanation: string;
}

export interface ResponseInspectionResult {
  riskScore: number;
  decision: DecisionType;
  findings: InspectionFinding[];
  originalText: string;
  redactedText: string;
  inspectedAt: string;
  sanitized: boolean;
}

export interface OverviewMetrics {
  totalToolCalls: number;
  allowedCalls: number;
  blockedCalls: number;
  approvalRequiredCalls: number;
  redactionsCount: number;
  activeThreatsCount: number;
  trends: {
    totalCallsDeltaPct: number;
    blockedDeltaPct: number;
    threatsDeltaPct: number;
  };
}

export interface GatewayStatus {
  online: boolean;
  version: string;
  uptimeSeconds: number;
  connectedServersCount: number;
  policyEngineActive: boolean;
  detectionEngineActive: boolean;
  lastEventTimestamp: string;
  backendUrl: string;
  isMock: boolean;
}

export type NavigationPage = 
  | 'overview'
  | 'live-monitor'
  | 'tool-calls'
  | 'threats'
  | 'policies'
  | 'mcp-servers'
  | 'response-inspector'
  | 'approvals'
  | 'audit-logs'
  | 'analytics'
  | 'settings';
