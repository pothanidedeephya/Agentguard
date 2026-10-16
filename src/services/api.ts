/**
 * Centralized API Client for AgentGuard Backend
 * Connects frontend to Express Gateway + PostgreSQL
 */
import {
  GatewayStatus,
  OverviewMetrics,
  ToolCall,
  ThreatEvent,
  AuditLog,
  PolicyRule,
  MCPServer,
  ApprovalRequest,
  ResponseInspectionResult,
} from '../types/agentguard';

export interface BackendHealthResponse {
  status: string;
  timestamp: string;
  uptimeSeconds: number;
  database: {
    state: 'CONNECTED' | 'DISCONNECTED' | 'NOT_CONFIGURED';
    host?: string | null;
    lastChecked: string;
    error?: string | null;
  };
  version: string;
}

// Retrieve configured API Base URL from env or localStorage
export function getApiBaseUrl(): string {
  const custom = localStorage.getItem('agentguard_api_url');
  if (custom !== null) {
    return custom.trim();
  }
  return (import.meta.env.VITE_API_BASE_URL as string) || '';
}

export function setApiBaseUrl(url: string): void {
  if (!url) {
    localStorage.removeItem('agentguard_api_url');
  } else {
    localStorage.setItem('agentguard_api_url', url.trim());
  }
}

// Safe fetch wrapper with timeout
async function request<T>(endpoint: string, options: RequestInit = {}, timeoutMs = 5000): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl.replace(/\/$/, '')}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(options.headers || {}),
      },
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      let errDetail = `${res.status} ${res.statusText}`;
      try {
        const json = await res.json();
        if (json && (json.error || json.message)) {
          errDetail = json.error || json.message;
        }
      } catch {
        // ignore json parse error
      }
      throw new Error(errDetail);
    }

    return (await res.json()) as T;
  } catch (error: unknown) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('API Request timed out after 5 seconds');
    }
    throw error;
  }
}

export const agentGuardApi = {
  // Health & Gateway status
  async checkHealth(): Promise<BackendHealthResponse> {
    return request<BackendHealthResponse>('/health', { method: 'GET' }, 3000);
  },

  async getGatewayStatus(): Promise<GatewayStatus> {
    return request<GatewayStatus>('/api/gateway/status');
  },

  // Overview metrics & charts from PostgreSQL
  async getOverviewMetrics(isDemo = false): Promise<OverviewMetrics> {
    return request<OverviewMetrics>(`/api/overview?demo=${isDemo}`);
  },

  async getVolumeAnalytics(interval: '15m' | '1h' | '24h' | '7d', isDemo = false) {
    return request<any[]>(`/api/analytics/volume?interval=${interval}&demo=${isDemo}`);
  },

  async getThreatCategories(isDemo = false) {
    return request<any[]>(`/api/analytics/threats-breakdown?demo=${isDemo}`);
  },

  async getRiskHistogram(isDemo = false) {
    return request<any[]>(`/api/analytics/risk-histogram?demo=${isDemo}`);
  },

  async getTopTools(isDemo = false) {
    return request<{ topInvoked: any[]; topBlocked: any[] }>(`/api/analytics/top-tools?demo=${isDemo}`);
  },

  // Tool calls
  async getToolCalls(options: {
    search?: string;
    server?: string;
    decision?: string;
    minRisk?: number;
    limit?: number;
    isDemo?: boolean;
  } = {}): Promise<ToolCall[]> {
    const params = new URLSearchParams();
    if (options.search) params.append('search', options.search);
    if (options.server && options.server !== 'ALL') params.append('server', options.server);
    if (options.decision && options.decision !== 'ALL') params.append('decision', options.decision);
    if (options.minRisk !== undefined) params.append('minRisk', String(options.minRisk));
    if (options.limit) params.append('limit', String(options.limit));
    if (options.isDemo !== undefined) params.append('demo', String(options.isDemo));

    const qs = params.toString();
    return request<ToolCall[]>(`/api/tool-calls${qs ? `?${qs}` : ''}`);
  },

  // Threats
  async getThreats(options: {
    category?: string;
    severity?: string;
    status?: string;
    search?: string;
    isDemo?: boolean;
  } = {}): Promise<ThreatEvent[]> {
    const params = new URLSearchParams();
    if (options.category && options.category !== 'ALL') params.append('category', options.category);
    if (options.severity && options.severity !== 'ALL') params.append('severity', options.severity);
    if (options.status && options.status !== 'ALL') params.append('status', options.status);
    if (options.search) params.append('search', options.search);
    if (options.isDemo !== undefined) params.append('demo', String(options.isDemo));

    const qs = params.toString();
    return request<ThreatEvent[]>(`/api/threats${qs ? `?${qs}` : ''}`);
  },

  async updateThreatStatus(id: string, status: ThreatEvent['status']): Promise<{ success: boolean; message: string }> {
    return request<{ success: boolean; message: string }>(`/api/threats/${id}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
  },

  // Audit logs
  async getAuditLogs(options: {
    search?: string;
    eventType?: string;
    startDate?: string;
    endDate?: string;
    isDemo?: boolean;
    limit?: number;
  } = {}): Promise<AuditLog[]> {
    const params = new URLSearchParams();
    if (options.search) params.append('search', options.search);
    if (options.eventType && options.eventType !== 'ALL') params.append('eventType', options.eventType);
    if (options.startDate) params.append('startDate', options.startDate);
    if (options.endDate) params.append('endDate', options.endDate);
    if (options.limit) params.append('limit', String(options.limit));
    if (options.isDemo !== undefined) params.append('demo', String(options.isDemo));

    const qs = params.toString();
    return request<AuditLog[]>(`/api/audit-logs${qs ? `?${qs}` : ''}`);
  },

  // Policies
  async getPolicies(): Promise<PolicyRule[]> {
    return request<PolicyRule[]>('/api/policies');
  },

  async updatePolicy(policy: PolicyRule): Promise<PolicyRule> {
    return request<PolicyRule>('/api/policies', {
      method: 'PUT',
      body: JSON.stringify(policy),
    });
  },

  // MCP Servers
  async getMcpServers(): Promise<MCPServer[]> {
    return request<MCPServer[]>('/api/mcp-servers');
  },

  async updateToolAllowlist(serverId: string, toolName: string, isAllowed: boolean): Promise<{ success: boolean; message: string }> {
    return request<{ success: boolean; message: string }>(`/api/mcp-servers/${serverId}/tools/${encodeURIComponent(toolName)}`, {
      method: 'PUT',
      body: JSON.stringify({ isAllowed }),
    });
  },

  async pingServer(serverId: string): Promise<{ success: boolean; latencyMs: number; lastPing: string }> {
    return request<{ success: boolean; latencyMs: number; lastPing: string }>(`/api/mcp-servers/${serverId}/ping`, {
      method: 'POST',
    });
  },

  // Approvals
  async getApprovals(status = 'ALL', isDemo = false): Promise<ApprovalRequest[]> {
    return request<ApprovalRequest[]>(`/api/approvals?status=${status}&demo=${isDemo}`);
  },

  async decideApproval(id: string, action: 'APPROVED' | 'REJECTED', notes: string, reviewer?: string): Promise<{ success: boolean; message: string; approval?: ApprovalRequest }> {
    return request<{ success: boolean; message: string; approval?: ApprovalRequest }>(`/api/approvals/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({ action, analystNotes: notes, reviewer }),
    });
  },

  // Evaluation & DLP
  async evaluateToolCall(payload: {
    agentId?: string;
    agentName?: string;
    serverName: string;
    serverId?: string;
    toolName: string;
    parameters: Record<string, unknown>;
    isDemo?: boolean;
  }): Promise<{
    callId: string;
    decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'REDACT';
    riskScore: number;
    status: ToolCall['status'];
    reasons: string[];
    threats: string[];
    durationMs: number;
    auditId: string;
  }> {
    return request('/api/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async inspectResponse(payload: {
    toolName: string;
    responsePayload: string;
    isDemo?: boolean;
  }): Promise<ResponseInspectionResult> {
    return request<ResponseInspectionResult>('/api/inspect-response', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  // Database Management
  async testDbConnection(connectionString?: string): Promise<{
    state: 'CONNECTED' | 'DISCONNECTED' | 'NOT_CONFIGURED';
    lastChecked: string;
    host?: string;
    database?: string;
    error?: string;
  }> {
    return request('/api/db/test-connection', {
      method: 'POST',
      body: JSON.stringify({ connectionString }),
    });
  },

  async runDbMigrations(): Promise<{ success: boolean; message: string; tablesCreated?: string[]; durationMs: number }> {
    return request('/api/db/run-migrations', {
      method: 'POST',
    });
  },
};
