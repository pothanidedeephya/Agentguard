/**
 * AgentGuard Security Context
 * State management supporting three explicit states: LIVE (PostgreSQL), DEMO, and DISCONNECTED
 */
import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import {
  ToolCall,
  ThreatEvent,
  PolicyRule,
  MCPServer,
  ApprovalRequest,
  AuditLog,
  OverviewMetrics,
  GatewayStatus,
  NavigationPage,
  DecisionType,
} from '../types/agentguard';
import {
  INITIAL_METRICS,
  DEMO_METRICS,
  INITIAL_GATEWAY_STATUS,
  INITIAL_POLICIES,
  INITIAL_MCP_SERVERS,
  INITIAL_TOOL_CALLS,
  INITIAL_THREATS,
  INITIAL_APPROVALS,
  INITIAL_AUDIT_LOGS,
  DEMO_SCENARIOS,
  DemoScenario,
} from '../services/mockData';
import { agentGuardApi, getApiBaseUrl, setApiBaseUrl } from '../services/api';

export type SystemOperatingState = 'LIVE' | 'DEMO' | 'DISCONNECTED';

interface SecurityContextType {
  currentPage: NavigationPage;
  setCurrentPage: (page: NavigationPage) => void;

  // Operating State: LIVE (PostgreSQL connected), DEMO (Synthetic), DISCONNECTED
  operatingState: SystemOperatingState;
  isBackendConnected: boolean;
  isDemoMode: boolean;
  setIsDemoMode: (val: boolean) => void;
  isCheckingConnection: boolean;
  backendUrl: string;
  updateBackendUrl: (url: string) => Promise<boolean>;
  checkBackendConnection: () => Promise<boolean>;
  gatewayStatus: GatewayStatus;

  // Database Connection Diagnostics
  dbState: 'CONNECTED' | 'DISCONNECTED' | 'NOT_CONFIGURED';
  dbHost: string | null;
  dbError: string | null;
  testCustomDbConnection: (url: string) => Promise<{ state: string; error?: string }>;
  triggerMigrations: () => Promise<{ success: boolean; message: string }>;

  // Data Collections
  metrics: OverviewMetrics;
  toolCalls: ToolCall[];
  threats: ThreatEvent[];
  policies: PolicyRule[];
  mcpServers: MCPServer[];
  approvals: ApprovalRequest[];
  auditLogs: AuditLog[];

  // Live Monitor Stream controls
  isLiveStreamActive: boolean;
  setIsLiveStreamActive: (active: boolean) => void;
  streamSpeedSeconds: number;
  setStreamSpeedSeconds: (sec: number) => void;
  clearLiveStream: () => void;
  refreshAllData: () => Promise<void>;

  // Policy Engine operations
  updatePolicy: (policy: PolicyRule) => Promise<{ success: boolean; message: string }>;
  addPolicy: (policy: Omit<PolicyRule, 'id' | 'lastUpdated'>) => Promise<{ success: boolean; message: string }>;

  // Approval operations
  handleApprovalAction: (
    approvalId: string,
    action: 'APPROVED' | 'REJECTED',
    analystNotes: string
  ) => Promise<{ success: boolean; message: string }>;

  // Threat operations
  updateThreatStatus: (threatId: string, status: ThreatEvent['status']) => Promise<void>;

  // MCP Servers operations
  toggleToolAllowlist: (serverId: string, toolName: string, isAllowed: boolean) => Promise<void>;
  pingMcpServer: (serverId: string) => Promise<number>;

  // Scenarios
  scenarios: DemoScenario[];
  runScenario: (scenarioId: string) => Promise<ToolCall>;
  lastScenarioRun: { scenarioName: string; decision: DecisionType; time: string } | null;

  // Selected entities for inspection modals
  selectedToolCall: ToolCall | null;
  setSelectedToolCall: (call: ToolCall | null) => void;
  selectedThreat: ThreatEvent | null;
  setSelectedThreat: (threat: ThreatEvent | null) => void;
}

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentPage, setCurrentPage] = useState<NavigationPage>('overview');
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);
  const [isCheckingConnection, setIsCheckingConnection] = useState<boolean>(false);
  const [backendUrl, setBackendUrlState] = useState<string>(getApiBaseUrl());

  // Database State
  const [dbState, setDbState] = useState<'CONNECTED' | 'DISCONNECTED' | 'NOT_CONFIGURED'>('NOT_CONFIGURED');
  const [dbHost, setDbHost] = useState<string | null>(null);
  const [dbError, setDbError] = useState<string | null>(null);

  // Core Data Collections
  const [gatewayStatus, setGatewayStatus] = useState<GatewayStatus>(INITIAL_GATEWAY_STATUS);
  const [metrics, setMetrics] = useState<OverviewMetrics>(INITIAL_METRICS);
  const [toolCalls, setToolCalls] = useState<ToolCall[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [policies, setPolicies] = useState<PolicyRule[]>(INITIAL_POLICIES);
  const [mcpServers, setMcpServers] = useState<MCPServer[]>(INITIAL_MCP_SERVERS);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  // Stream controls
  const [isLiveStreamActive, setIsLiveStreamActive] = useState<boolean>(true);
  const [streamSpeedSeconds, setStreamSpeedSeconds] = useState<number>(4);

  // Modals & Selection
  const [selectedToolCall, setSelectedToolCall] = useState<ToolCall | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null);
  const [lastScenarioRun, setLastScenarioRun] = useState<{ scenarioName: string; decision: DecisionType; time: string } | null>(null);

  // Compute operating state: LIVE, DEMO, or DISCONNECTED
  const operatingState: SystemOperatingState = isDemoMode
    ? 'DEMO'
    : isBackendConnected && dbState === 'CONNECTED'
    ? 'LIVE'
    : 'DISCONNECTED';

  // Fetch all live data from backend repositories
  const refreshAllData = useCallback(async () => {
    if (!isBackendConnected || dbState !== 'CONNECTED') return;

    try {
      const [overviewData, callsData, threatsData, policiesData, serversData, approvalsData, auditData] =
        await Promise.allSettled([
          agentGuardApi.getOverviewMetrics(false),
          agentGuardApi.getToolCalls({ isDemo: false, limit: 50 }),
          agentGuardApi.getThreats({ isDemo: false }),
          agentGuardApi.getPolicies(),
          agentGuardApi.getMcpServers(),
          agentGuardApi.getApprovals('ALL', false),
          agentGuardApi.getAuditLogs({ isDemo: false, limit: 50 }),
        ]);

      if (overviewData.status === 'fulfilled') setMetrics(overviewData.value);
      if (callsData.status === 'fulfilled') setToolCalls(callsData.value);
      if (threatsData.status === 'fulfilled') setThreats(threatsData.value);
      if (policiesData.status === 'fulfilled') setPolicies(policiesData.value);
      if (serversData.status === 'fulfilled') setMcpServers(serversData.value);
      if (approvalsData.status === 'fulfilled') setApprovals(approvalsData.value);
      if (auditData.status === 'fulfilled') setAuditLogs(auditData.value);
    } catch (err) {
      console.warn('[AgentGuard Context] Refresh error:', err);
    }
  }, [isBackendConnected, dbState]);

  const handleSetIsDemoMode = useCallback(
    (val: boolean) => {
      setIsDemoMode(val);
      if (val) {
        setMetrics(DEMO_METRICS);
        setToolCalls(INITIAL_TOOL_CALLS);
        setThreats(INITIAL_THREATS);
        setApprovals(INITIAL_APPROVALS);
        setAuditLogs(INITIAL_AUDIT_LOGS);
      } else {
        if (dbState === 'CONNECTED') {
          refreshAllData();
        } else {
          setMetrics(INITIAL_METRICS);
          setToolCalls([]);
          setThreats([]);
          setApprovals([]);
          setAuditLogs([]);
        }
      }
    },
    [dbState, refreshAllData]
  );

  // Check backend health & database status
  const checkBackendConnection = useCallback(async (): Promise<boolean> => {
    setIsCheckingConnection(true);
    try {
      const health = await agentGuardApi.checkHealth();
      setIsBackendConnected(true);

      if (health.database) {
        setDbState(health.database.state);
        setDbHost(health.database.host || null);
        setDbError(health.database.error || null);

        if (health.database.state === 'CONNECTED') {
          // If DB is connected and user hasn't explicitly locked into DEMO mode, go LIVE!
          setIsDemoMode(false);
          setGatewayStatus((prev) => ({
            ...prev,
            online: true,
            isMock: false,
            backendUrl: health.database.host ? `PostgreSQL (${health.database.host})` : 'Connected',
          }));

          // Initial data population from PostgreSQL
          try {
            const [overviewData, callsData, threatsData, policiesData, serversData, approvalsData, auditData] =
              await Promise.allSettled([
                agentGuardApi.getOverviewMetrics(false),
                agentGuardApi.getToolCalls({ isDemo: false, limit: 50 }),
                agentGuardApi.getThreats({ isDemo: false }),
                agentGuardApi.getPolicies(),
                agentGuardApi.getMcpServers(),
                agentGuardApi.getApprovals('ALL', false),
                agentGuardApi.getAuditLogs({ isDemo: false, limit: 50 }),
              ]);

            if (overviewData.status === 'fulfilled') setMetrics(overviewData.value);
            if (callsData.status === 'fulfilled') setToolCalls(callsData.value);
            if (threatsData.status === 'fulfilled') setThreats(threatsData.value);
            if (policiesData.status === 'fulfilled') setPolicies(policiesData.value);
            if (serversData.status === 'fulfilled') setMcpServers(serversData.value);
            if (approvalsData.status === 'fulfilled') setApprovals(approvalsData.value);
            if (auditData.status === 'fulfilled') setAuditLogs(auditData.value);
          } catch (e) {
            console.error('[AgentGuard Context] Initial DB fetch failed:', e);
          }
        } else {
          // Database is not configured or disconnected
          setGatewayStatus((prev) => ({
            ...prev,
            online: true,
            isMock: true,
            backendUrl: 'Gateway active (PostgreSQL Disconnected)',
          }));
        }
      }

      setIsCheckingConnection(false);
      return true;
    } catch (err: unknown) {
      // Backend daemon completely unreachable
      setIsBackendConnected(false);
      setDbState('DISCONNECTED');
      setDbError(err instanceof Error ? err.message : 'Backend unreachable');
      setGatewayStatus((prev) => ({
        ...prev,
        online: false,
        isMock: true,
      }));
      setIsCheckingConnection(false);
      return false;
    }
  }, []);

  const updateBackendUrl = async (newUrl: string): Promise<boolean> => {
    setApiBaseUrl(newUrl);
    setBackendUrlState(newUrl);
    return await checkBackendConnection();
  };

  const testCustomDbConnection = async (url: string) => {
    const res = await agentGuardApi.testDbConnection(url);
    if (res.state === 'CONNECTED') {
      setDbState('CONNECTED');
      setDbHost(res.host || null);
      setDbError(null);
      await checkBackendConnection();
    }
    return res;
  };

  const triggerMigrations = async () => {
    const res = await agentGuardApi.runDbMigrations();
    if (res.success) {
      await refreshAllData();
    }
    return res;
  };

  // Initial connection probe on mount
  useEffect(() => {
    checkBackendConnection();
  }, [checkBackendConnection]);

  // Live polling / stream timer
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!isLiveStreamActive) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      return;
    }

    const intervalMs = streamSpeedSeconds * 1000;
    pollTimerRef.current = setInterval(async () => {
      // In LIVE mode, poll real database tool calls and metrics
      if (isBackendConnected && dbState === 'CONNECTED' && !isDemoMode) {
        try {
          const [calls, overview, thrs, apprs, auds] = await Promise.all([
            agentGuardApi.getToolCalls({ isDemo: false, limit: 50 }),
            agentGuardApi.getOverviewMetrics(false),
            agentGuardApi.getThreats({ isDemo: false }),
            agentGuardApi.getApprovals('ALL', false),
            agentGuardApi.getAuditLogs({ isDemo: false, limit: 50 }),
          ]);
          setToolCalls(calls);
          setMetrics(overview);
          setThreats(thrs);
          setApprovals(apprs);
          setAuditLogs(auds);
        } catch {
          // ignore transient poll error
        }
        return;
      }

      // In DEMO mode, produce periodic synthetic event
      if (isDemoMode) {
        const sampleTools = [
          {
            agent: 'CodeReviewAgent',
            server: 'filesystem-mcp',
            serverId: 'srv-fs-01',
            tool: 'read_file',
            params: { path: `src/modules/service-${Math.floor(Math.random() * 8) + 1}.ts` },
            decision: 'ALLOW' as DecisionType,
            risk: Math.floor(Math.random() * 20) + 5,
            status: 'EXECUTED' as const,
            reasons: ['Normalized repository workspace path', 'Zero policy violations'],
          },
          {
            agent: 'SupportHelpdeskBot',
            server: 'postgres-mcp',
            serverId: 'srv-db-02',
            tool: 'execute_query',
            params: { sql: `SELECT id, name, status FROM accounts WHERE tenant_id = ${Math.floor(Math.random() * 500)}` },
            decision: 'ALLOW' as DecisionType,
            risk: Math.floor(Math.random() * 25) + 10,
            status: 'EXECUTED' as const,
            reasons: ['Read-only SELECT query against replica', 'Tenant isolation verified'],
          },
        ];

        const sample = sampleTools[Math.floor(Math.random() * sampleTools.length)];
        const id = `call-demo-${Math.floor(10000 + Math.random() * 90000)}`;
        const timestamp = new Date().toISOString();

        const newCall: ToolCall = {
          id,
          timestamp,
          agentId: sample.agent.toLowerCase(),
          agentName: sample.agent,
          serverName: sample.server,
          serverId: sample.serverId,
          toolName: sample.tool,
          inputParams: sample.params,
          riskScore: sample.risk,
          decision: sample.decision,
          status: sample.status,
          durationMs: Math.floor(Math.random() * 50) + 12,
          detectionReasons: sample.reasons,
          auditId: `aud-${Math.floor(1000 + Math.random() * 9000)}`,
          isSimulated: true,
        };

        setToolCalls((prev) => [newCall, ...prev.slice(0, 49)]);
        setMetrics((prev) => ({
          ...prev,
          totalToolCalls: prev.totalToolCalls + 1,
          allowedCalls: prev.allowedCalls + 1,
        }));
      }
    }, intervalMs);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [isLiveStreamActive, streamSpeedSeconds, isBackendConnected, dbState, isDemoMode]);

  const clearLiveStream = () => {
    setToolCalls([]);
  };

  // Policy Engine operations
  const updatePolicy = async (policy: PolicyRule): Promise<{ success: boolean; message: string }> => {
    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        const updated = await agentGuardApi.updatePolicy(policy);
        setPolicies((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
        await refreshAllData();
        return { success: true, message: `Policy "${policy.name}" updated in PostgreSQL.` };
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Database error';
        return { success: false, message: `Failed to update policy in PostgreSQL: ${msg}` };
      }
    } else {
      // Local demo update
      setPolicies((prev) =>
        prev.map((p) =>
          p.id === policy.id ? { ...policy, lastUpdated: new Date().toISOString() } : p
        )
      );
      return { success: true, message: `[Demo Mode] Policy "${policy.name}" updated locally.` };
    }
  };

  const addPolicy = async (policyData: Omit<PolicyRule, 'id' | 'lastUpdated'>): Promise<{ success: boolean; message: string }> => {
    const newPolicy: PolicyRule = {
      ...policyData,
      id: `pol-${String(policies.length + 1).padStart(3, '0')}`,
      lastUpdated: new Date().toISOString(),
    };

    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        const saved = await agentGuardApi.updatePolicy(newPolicy);
        setPolicies((prev) => [...prev, saved]);
        await refreshAllData();
        return { success: true, message: `Policy created in PostgreSQL with ID ${saved.id}` };
      } catch (err: unknown) {
        return { success: false, message: `Failed to insert policy: ${err instanceof Error ? err.message : 'Error'}` };
      }
    } else {
      setPolicies((prev) => [...prev, newPolicy]);
      return { success: true, message: `[Demo Mode] Policy created locally with ID ${newPolicy.id}` };
    }
  };

  // Approval operations
  const handleApprovalAction = async (
    approvalId: string,
    action: 'APPROVED' | 'REJECTED',
    analystNotes: string
  ): Promise<{ success: boolean; message: string }> => {
    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        const res = await agentGuardApi.decideApproval(approvalId, action, analystNotes);
        await refreshAllData();
        return { success: true, message: res.message };
      } catch (err: unknown) {
        return { success: false, message: `Database approval update failed: ${err instanceof Error ? err.message : 'Error'}` };
      }
    } else {
      const targetApproval = approvals.find((a) => a.id === approvalId);
      if (!targetApproval) return { success: false, message: 'Approval request not found.' };

      setApprovals((prev) =>
        prev.map((a) =>
          a.id === approvalId
            ? { ...a, status: action, reviewer: 'analyst@agentguard.internal', reviewedAt: new Date().toISOString(), analystNotes }
            : a
        )
      );
      return { success: true, message: `[Demo Mode] Request ${action}. (Backend not connected; execution not resumed).` };
    }
  };

  // Threat operations
  const updateThreatStatus = async (threatId: string, status: ThreatEvent['status']): Promise<void> => {
    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        await agentGuardApi.updateThreatStatus(threatId, status);
        await refreshAllData();
      } catch {
        // fallback local
        setThreats((prev) => prev.map((t) => (t.id === threatId ? { ...t, status } : t)));
      }
    } else {
      setThreats((prev) => prev.map((t) => (t.id === threatId ? { ...t, status } : t)));
    }
  };

  // MCP Servers operations
  const toggleToolAllowlist = async (serverId: string, toolName: string, isAllowed: boolean): Promise<void> => {
    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        await agentGuardApi.updateToolAllowlist(serverId, toolName, isAllowed);
        const servers = await agentGuardApi.getMcpServers();
        setMcpServers(servers);
      } catch {
        // fallback
        setMcpServers((prev) =>
          prev.map((s) =>
            s.id === serverId
              ? { ...s, tools: s.tools.map((t) => (t.name === toolName ? { ...t, isAllowed } : t)) }
              : s
          )
        );
      }
    } else {
      setMcpServers((prev) =>
        prev.map((s) =>
          s.id === serverId
            ? { ...s, tools: s.tools.map((t) => (t.name === toolName ? { ...t, isAllowed } : t)) }
            : s
        )
      );
    }
  };

  const pingMcpServer = async (serverId: string): Promise<number> => {
    if (isBackendConnected && dbState === 'CONNECTED') {
      try {
        const res = await agentGuardApi.pingServer(serverId);
        const servers = await agentGuardApi.getMcpServers();
        setMcpServers(servers);
        return res.latencyMs;
      } catch {
        return 20;
      }
    } else {
      const lat = 18;
      setMcpServers((prev) =>
        prev.map((s) => (s.id === serverId ? { ...s, latencyMs: lat, lastPing: new Date().toISOString() } : s))
      );
      return lat;
    }
  };

  // Deterministic Scenario Execution (persists to DB via POST /api/evaluate)
  const runScenario = async (scenarioId: string): Promise<ToolCall> => {
    const scenario = DEMO_SCENARIOS.find((s) => s.id === scenarioId);
    if (!scenario) throw new Error('Scenario not found');

    const shouldPersistAsDemo = operatingState !== 'LIVE';

    try {
      // Evaluate via real backend security pipeline
      const evalRes = await agentGuardApi.evaluateToolCall({
        agentId: scenario.payload.agentId,
        agentName: scenario.payload.agentName,
        serverName: scenario.payload.serverName,
        serverId: scenario.payload.serverId,
        toolName: scenario.payload.toolName,
        parameters: scenario.payload.inputParams,
        isDemo: shouldPersistAsDemo,
      });

      const call: ToolCall = {
        id: evalRes.callId,
        timestamp: new Date().toISOString(),
        agentId: scenario.payload.agentId,
        agentName: scenario.payload.agentName,
        serverName: scenario.payload.serverName,
        serverId: scenario.payload.serverId,
        toolName: scenario.payload.toolName,
        inputParams: scenario.payload.inputParams,
        riskScore: evalRes.riskScore,
        decision: evalRes.decision,
        status: evalRes.status,
        durationMs: evalRes.durationMs,
        detectionReasons: evalRes.reasons,
        auditId: evalRes.auditId,
        isSimulated: shouldPersistAsDemo,
      };

      setLastScenarioRun({
        scenarioName: scenario.name,
        decision: evalRes.decision,
        time: new Date().toLocaleTimeString(),
      });

      // Refresh data from PostgreSQL
      if (operatingState === 'LIVE') {
        await refreshAllData();
      } else {
        setToolCalls((prev) => [call, ...prev]);
      }

      return call;
    } catch (err) {
      console.warn('[AgentGuard] Remote evaluation failed, running client fallback:', err);
      // Fallback local execution if backend offline
      const call: ToolCall = {
        id: `call-local-${Date.now().toString().slice(-5)}`,
        timestamp: new Date().toISOString(),
        agentId: scenario.payload.agentId,
        agentName: scenario.payload.agentName,
        serverName: scenario.payload.serverName,
        serverId: scenario.payload.serverId,
        toolName: scenario.payload.toolName,
        inputParams: scenario.payload.inputParams,
        riskScore: scenario.expectedDecision === 'BLOCK' ? 98 : 10,
        decision: scenario.expectedDecision,
        status: scenario.expectedDecision === 'BLOCK' ? 'BLOCKED' : 'EXECUTED',
        durationMs: 25,
        detectionReasons: ['Fallback local evaluation rule'],
        auditId: `aud-${Date.now()}`,
        isSimulated: true,
      };
      setToolCalls((prev) => [call, ...prev]);
      return call;
    }
  };

  return (
    <SecurityContext.Provider
      value={{
        currentPage,
        setCurrentPage,
        operatingState,
        isBackendConnected,
        isDemoMode,
        setIsDemoMode: handleSetIsDemoMode,
        isCheckingConnection,
        backendUrl,
        updateBackendUrl,
        checkBackendConnection,
        gatewayStatus,
        dbState,
        dbHost,
        dbError,
        testCustomDbConnection,
        triggerMigrations,
        metrics,
        toolCalls,
        threats,
        policies,
        mcpServers,
        approvals,
        auditLogs,
        isLiveStreamActive,
        setIsLiveStreamActive,
        streamSpeedSeconds,
        setStreamSpeedSeconds,
        clearLiveStream,
        refreshAllData,
        updatePolicy,
        addPolicy,
        handleApprovalAction,
        updateThreatStatus,
        toggleToolAllowlist,
        pingMcpServer,
        scenarios: DEMO_SCENARIOS,
        runScenario,
        lastScenarioRun,
        selectedToolCall,
        setSelectedToolCall,
        selectedThreat,
        setSelectedThreat,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = (): SecurityContextType => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
