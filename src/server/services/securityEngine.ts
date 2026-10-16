/**
 * AgentGuard MCP Runtime Security Evaluation Engine
 * Evaluates tool calls, enforces policies, detects threats, and records persistent database telemetry.
 * Strictly guarantees that blocked or quarantined calls NEVER reach downstream MCP tools.
 */
import crypto from 'crypto';
import { toolCallsRepository } from '../repositories/toolCallsRepository';
import { threatsRepository } from '../repositories/threatsRepository';
import { policiesRepository } from '../repositories/policiesRepository';
import { auditLogsRepository } from '../repositories/auditLogsRepository';
import { mcpServersRepository } from '../repositories/mcpServersRepository';
import { approvalsRepository } from '../repositories/approvalsRepository';
import { ToolCall, ThreatEvent, AuditLog, DecisionType, ThreatCategory } from '../../types/agentguard';
import { getDbPool } from '../db/pool';
import { downstreamExecutor, DownstreamExecutionResult } from '../mcp/downstreamExecutor';

export interface EvaluateRequest {
  agentId?: string;
  agentName?: string;
  serverName: string;
  serverId?: string;
  toolName: string;
  parameters: Record<string, unknown>;
  executeDownstream?: boolean;
  isDemo?: boolean;
}

export interface EvaluateResponse {
  callId: string;
  decision: DecisionType;
  riskScore: number;
  status: ToolCall['status'];
  reasons: string[];
  threats: string[];
  durationMs: number;
  auditId: string;
  approvalId?: string;
  downstreamExecuted: boolean;
  result?: unknown;
}

export const securityEngine = {
  /**
   * Evaluates security policies and executes downstream ONLY if permitted.
   */
  async evaluateToolCall(req: EvaluateRequest): Promise<EvaluateResponse> {
    const startTime = Date.now();
    const callId = `call-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
    const auditId = `aud-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const agentName = req.agentName || req.agentId || 'AutonomousAgent';
    const serverName = req.serverName || 'filesystem-mcp';
    const toolName = req.toolName || 'read_file';
    const params = req.parameters || {};
    const paramString = JSON.stringify(params);

    // Fetch active policies from DB if available
    let activePolicies: any[] = [];
    let serverRecord: any = null;
    const pool = getDbPool();

    if (pool) {
      try {
        activePolicies = await policiesRepository.findAll();
        const allServers = await mcpServersRepository.findAll();
        serverRecord = allServers.find(
          (s) => s.name.toLowerCase() === serverName.toLowerCase() || s.id === (req.serverId || serverName)
        );
      } catch (e) {
        console.warn('[Security Engine] Could not load DB configuration, using baseline security rules');
      }
    }

    let riskScore = 5;
    let decision: DecisionType = 'ALLOW';
    const reasons: string[] = [];
    const detectedThreats: {
      category: ThreatCategory;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      title: string;
      evidence: string;
      rule: string;
      action: string;
    }[] = [];

    // Check 1: Tool Allowlist Check on target MCP Server
    if (serverRecord && Array.isArray(serverRecord.tools)) {
      const toolConfig = serverRecord.tools.find((t: any) => t.name === toolName);
      if (toolConfig && toolConfig.isAllowed === false) {
        riskScore = Math.max(riskScore, 92);
        decision = 'BLOCK';
        reasons.push(`Tool '${toolName}' is disabled in allowlist on server '${serverName}'`);
        detectedThreats.push({
          category: 'UNAUTHORIZED_TOOL',
          severity: 'HIGH',
          title: `Unauthorized Invocation of Disabled Tool: ${toolName}`,
          evidence: `Agent attempted invocation of tool '${toolName}' which is toggled off in server policy.`,
          rule: 'RULE_SERVER_TOOL_ALLOWLIST',
          action: 'Reject invocation. Prompt administrator to review tool allowlist permissions.',
        });
      }
    }

    // Check 2: Directory Traversal Check & System Path Inspection
    const hasPathClimbing = /\.\.[\/\\]/.test(paramString) || /\.\.%2f/i.test(paramString) || /%2e%2e%2f/i.test(paramString);
    const targetsSystemPath = /\/etc\/|\/proc\/|\/sys\/|\/var\/run\/|C:\\Windows\\System32/i.test(paramString);
    if (hasPathClimbing || targetsSystemPath) {
      riskScore = Math.max(riskScore, 98);
      decision = 'BLOCK';
      const reason = hasPathClimbing 
        ? 'Pattern matched: directory traversal sequence (../)' 
        : 'Prohibited target path detected in parameters';
      reasons.push(reason);
      reasons.push('Policy pol-001 (Directory Traversal & Path Quarantine) enforced');
      detectedThreats.push({
        category: 'PATH_TRAVERSAL',
        severity: 'CRITICAL',
        title: 'Directory Traversal via Path Climbing Sequence',
        evidence: `Parameter inspection revealed relative traversal target: ${paramString.substring(0, 150)}`,
        rule: 'RULE_PATH_TRAVERSAL_DOT_DOT',
        action: 'Quarantine agent session. Prohibit filesystem access outside workspace boundaries.',
      });
    }

    // Check 3: Dangerous Shell Execution & Pipe Evasion
    const hasShellPipes = /(&&|\|\||;\s*(?:rm|curl|wget|sh|bash|powershell|cat|base64)|\|\s*(?:bash|sh|powershell|zsh|eval)|curl\s+.*\|\s*(?:sh|bash))/i.test(paramString);
    const isShellTool = toolName === 'run_command' || toolName === 'exec' || serverName.includes('shell');
    if (hasShellPipes) {
      riskScore = Math.max(riskScore, 100);
      decision = 'BLOCK';
      reasons.push('Prohibited shell command pipe or destructive operator detected');
      reasons.push('Policy pol-002 (Arbitrary Shell Execution Quarantine) enforced');
      detectedThreats.push({
        category: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        title: 'Arbitrary Shell Execution & Pipeline Evasion Attempt',
        evidence: `Shell command arguments contained prohibited execution chain: ${paramString.substring(0, 150)}`,
        rule: 'RULE_SHELL_PIPED_EXECUTION_AND_DELETION',
        action: 'Revoke agent authorization token. Verify host container integrity.',
      });
    } else if (isShellTool && riskScore < 90) {
      riskScore = Math.max(riskScore, 85);
      reasons.push('Privileged tool invocation on shell execution runtime');
    }

    // Check 4: Destructive Database DDL
    const hasDestructiveSql = /\b(DROP\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+TABLE.*DROP|DROP\s+DATABASE)\b/i.test(paramString);
    if (hasDestructiveSql) {
      riskScore = Math.max(riskScore, 94);
      decision = 'REQUIRE_APPROVAL';
      reasons.push('Destructive SQL DDL keyword detected (DROP/TRUNCATE)');
      reasons.push('Policy pol-003 (Database Destructive DDL Guard) halted call for human review');
    }

    // Check 5: Secret Exposure in Input Parameters
    const secretInInput = /(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9_-]{24,64}|ghp_[a-zA-Z0-9]{36}|-----BEGIN (?:RSA )?PRIVATE KEY-----)/.test(paramString);
    if (secretInInput) {
      riskScore = Math.max(riskScore, 86);
      if (decision === 'ALLOW') decision = 'REDACT';
      reasons.push('High-entropy API credential detected in tool arguments');
      detectedThreats.push({
        category: 'SECRET_LEAKAGE',
        severity: 'HIGH',
        title: 'API Token / Private Key Injected in Parameters',
        evidence: 'Arguments contain high-entropy credential pattern matching AWS/OpenAI/GitHub token syntax.',
        rule: 'RULE_INPUT_SECRET_EXPOSURE',
        action: 'Sanitize arguments and mask credentials before forwarding.',
      });
    }

    // Check 6: Match against custom DB policies
    for (const p of activePolicies) {
      if (!p.enabled) continue;
      const targetTools = p.targetTools || ['*'];
      const targetServers = p.targetServers || ['*'];
      const matchesServer = targetServers.includes('*') || targetServers.includes(serverName);
      const matchesTool = targetTools.includes('*') || targetTools.some((t: string) => t === toolName || t === `${serverName}/${toolName}`);

      if (matchesServer && matchesTool) {
        if (riskScore >= p.riskThreshold) {
          if (p.action === 'BLOCK') decision = 'BLOCK';
          else if (p.action === 'REQUIRE_APPROVAL' && decision !== 'BLOCK') decision = 'REQUIRE_APPROVAL';
          else if (p.action === 'REDACT' && decision === 'ALLOW') decision = 'REDACT';
          reasons.push(`Policy ${p.id} (${p.name}) applied: action=${p.action} for threshold >= ${p.riskThreshold}`);
        }
      }
    }

    if (reasons.length === 0) {
      reasons.push('Validated against active policy matrix');
      reasons.push('Zero security anomalies or traversal markers detected');
    }

    // Sanitize input if secret present
    let sanitizedParams = params;
    if (secretInInput || decision === 'REDACT') {
      const sanitizedStr = paramString
        .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA[REDACTED_AWS_KEY]')
        .replace(/sk-[a-zA-Z0-9_-]{24,64}/g, 'sk-[REDACTED_OPENAI_TOKEN]')
        .replace(/ghp_[a-zA-Z0-9]{36}/g, 'ghp_[REDACTED_GITHUB_PAT]')
        .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]');
      try {
        sanitizedParams = JSON.parse(sanitizedStr);
      } catch {
        sanitizedParams = params;
      }
    }

    // Execution Decision Enforcement:
    // A BLOCKED or PENDING_APPROVAL call must NEVER reach downstream!
    let downstreamExecuted = false;
    let downstreamResult: DownstreamExecutionResult | null = null;
    let sanitizedOutput: unknown = null;
    let approvalId: string | undefined = undefined;

    const executionStatus: ToolCall['status'] = 
      decision === 'BLOCK' ? 'BLOCKED' : 
      decision === 'REQUIRE_APPROVAL' ? 'PENDING_APPROVAL' : 
      'EXECUTED';

    if (decision === 'ALLOW' || decision === 'REDACT') {
      if (req.executeDownstream !== false) {
        // Execute downstream tool safely
        downstreamResult = await downstreamExecutor.execute(serverName, toolName, sanitizedParams);
        downstreamExecuted = downstreamResult.executed;

        // Perform post-execution Response DLP inspection
        const inspection = await this.inspectResponse(
          toolName,
          downstreamResult.rawOutputString,
          Boolean(req.isDemo)
        );

        if (inspection.sanitized) {
          decision = 'REDACT';
          sanitizedOutput = inspection.redactedText;
        } else {
          sanitizedOutput = downstreamResult.output;
        }
      }
    }

    const durationMs = Math.max(6, Date.now() - startTime);

    const callRecord: ToolCall & { isDemo?: boolean; sanitizedInput?: unknown; executedAt?: string } = {
      id: callId,
      timestamp,
      agentId: req.agentId || 'agent-autonomous',
      agentName,
      serverName,
      serverId: req.serverId || (serverRecord?.id || 'srv-generic'),
      toolName,
      inputParams: params,
      sanitizedInput: sanitizedParams,
      riskScore,
      decision,
      status: executionStatus,
      durationMs,
      detectionReasons: reasons,
      auditId,
      outputData: downstreamResult?.output,
      redactedOutput: sanitizedOutput,
      executedAt: downstreamExecuted ? new Date().toISOString() : undefined,
      isDemo: Boolean(req.isDemo),
    };

    // Persistent storage in PostgreSQL if pool is available
    if (pool) {
      try {
        await toolCallsRepository.create(callRecord);

        // Record threats if any
        for (const t of detectedThreats) {
          await threatsRepository.create({
            id: `thr-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`,
            timestamp,
            category: t.category,
            title: t.title,
            severity: t.severity,
            riskScore,
            sourceTool: `${serverName}/${toolName}`,
            serverName,
            agentName,
            toolCallId: callId,
            evidence: t.evidence,
            detectionRule: t.rule,
            recommendedAction: t.action,
            status: 'ACTIVE',
            isDemo: Boolean(req.isDemo),
          });
        }

        // Record audit log
        await auditLogsRepository.create({
          id: auditId,
          timestamp,
          actor: agentName,
          eventType: detectedThreats.length > 0 ? 'THREAT_DETECTED' : 'TOOL_EVALUATION',
          toolCallId: callId,
          decision,
          riskScore,
          reason: reasons[0] || 'Tool call policy evaluated',
          outcome: decision === 'BLOCK' ? 'BLOCKED' : decision === 'REQUIRE_APPROVAL' ? 'FLAGGED' : 'ALLOWED',
          ipAddress: '127.0.0.1',
          metadata: {
            serverName,
            toolName,
            downstreamExecuted,
            threatsCount: detectedThreats.length,
          },
          isDemo: Boolean(req.isDemo),
        });

        // Record metric in mcp_servers
        const targetServerId = req.serverId || serverRecord?.id;
        if (targetServerId) {
          await mcpServersRepository.recordCallMetric(targetServerId, toolName, decision === 'BLOCK').catch(() => {});
        }

        // If approval needed, insert into approval_requests
        if (decision === 'REQUIRE_APPROVAL') {
          approvalId = `appr-${Date.now().toString().slice(-5)}`;
          await approvalsRepository.create({
            id: approvalId,
            toolCallId: callId,
            timestamp,
            agentName,
            serverName,
            toolName,
            inputParams: params,
            riskScore,
            policyReason: reasons.find((r) => r.includes('pol-003')) || reasons[0],
            status: 'PENDING',
            isDemo: Boolean(req.isDemo),
          });
        }
      } catch (dbErr) {
        console.error('[Security Engine] Database write error:', dbErr);
      }
    }

    return {
      callId,
      decision,
      riskScore,
      status: executionStatus,
      reasons,
      threats: detectedThreats.map((t) => t.title),
      durationMs,
      auditId,
      approvalId,
      downstreamExecuted,
      result: sanitizedOutput || downstreamResult?.output,
    };
  },

  /**
   * Response DLP Inspector: Scans downstream tool responses for credentials, PII, and injection.
   */
  async inspectResponse(toolName: string, rawPayload: string | Record<string, unknown>, isDemo = false, failClosed = false) {
    const rawText = typeof rawPayload === 'object' ? JSON.stringify(rawPayload) : String(rawPayload);
    const findings: { type: string; confidence: string; matchSnippet: string; position: { start: number; end: number }; explanation: string }[] = [];
    let redacted = rawText;
    let riskScore = 0;

    // 1. API Keys & Secrets
    const apiKeyRegex = /(?:sk-[a-zA-Z0-9_-]{24,64}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})/g;
    let match: RegExpExecArray | null;
    while ((match = apiKeyRegex.exec(rawText)) !== null) {
      findings.push({
        type: 'API_KEY',
        confidence: 'HIGH',
        matchSnippet: match[0].substring(0, 8) + '...',
        position: { start: match.index, end: match.index + match[0].length },
        explanation: 'Exposed secret API key token detected with high entropy format.',
      });
      riskScore = Math.max(riskScore, 88);
    }
    redacted = redacted.replace(apiKeyRegex, (m) => `[REDACTED-TOKEN:${m.substring(0, 4)}...]`);

    // 2. US Social Security Numbers
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    while ((match = ssnRegex.exec(rawText)) !== null) {
      findings.push({
        type: 'PII_SSN',
        confidence: 'HIGH',
        matchSnippet: '***-**-****',
        position: { start: match.index, end: match.index + match[0].length },
        explanation: 'US Social Security Number pattern detected in tool output.',
      });
      riskScore = Math.max(riskScore, 85);
    }
    redacted = redacted.replace(ssnRegex, '[REDACTED-SSN:***-**-****]');

    // 3. Email Addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    while ((match = emailRegex.exec(rawText)) !== null) {
      findings.push({
        type: 'PII_EMAIL',
        confidence: 'HIGH',
        matchSnippet: match[0],
        position: { start: match.index, end: match.index + match[0].length },
        explanation: 'Customer personally identifiable email address found.',
      });
      riskScore = Math.max(riskScore, 45);
    }
    redacted = redacted.replace(emailRegex, (m) => `[REDACTED-EMAIL:${m.split('@')[0].substring(0, 2)}***@${m.split('@')[1]}]`);

    // 4. Phone Numbers
    const phoneRegex = /\b(?:\+?1[-.]?)?\(?[2-9]\d{2}\)?[-.]?\d{3}[-.]?\d{4}\b/g;
    while ((match = phoneRegex.exec(rawText)) !== null) {
      findings.push({
        type: 'PII_PHONE',
        confidence: 'MEDIUM',
        matchSnippet: match[0],
        position: { start: match.index, end: match.index + match[0].length },
        explanation: 'Phone number pattern detected in response.',
      });
      riskScore = Math.max(riskScore, 50);
    }
    redacted = redacted.replace(phoneRegex, '[REDACTED-PHONE]');

    // 5. Prompt Injection & Jailbreak Indicators
    const injectionPatterns = [
      /ignore\s+(?:all\s+)?previous\s+instructions/i,
      /you\s+are\s+now\s+in\s+developer\s+mode/i,
      /<system>.*?<\/system>/i,
      /override\s+security\s+guardrails/i,
      /reveal\s+system\s+prompt/i,
      /<\|im_start\|>system/i,
    ];

    for (const pattern of injectionPatterns) {
      const pMatch = pattern.exec(rawText);
      if (pMatch) {
        findings.push({
          type: 'PROMPT_INJECTION',
          confidence: 'HIGH',
          matchSnippet: pMatch[0],
          position: { start: pMatch.index, end: pMatch.index + pMatch[0].length },
          explanation: 'Jailbreak or instruction override directive targeting host LLM.',
        });
        riskScore = Math.max(riskScore, 95);
      }
    }

    let decision: DecisionType = 'ALLOW';
    if (riskScore >= 90) {
      decision = failClosed ? 'BLOCK' : 'BLOCK';
    } else if (riskScore >= 45) {
      decision = 'REDACT';
    }

    // Log DLP audit record if pool is active
    const pool = getDbPool();
    if (pool && findings.length > 0) {
      try {
        await auditLogsRepository.create({
          id: `aud-dlp-${Date.now().toString().slice(-6)}`,
          timestamp: new Date().toISOString(),
          actor: 'AgentGuard-DLP',
          eventType: 'DLP_INSPECTION',
          decision,
          riskScore,
          reason: `Response DLP sanitized ${findings.length} sensitive artifacts for tool ${toolName}`,
          outcome: decision === 'BLOCK' ? 'BLOCKED' : 'COMPLETED',
          ipAddress: '127.0.0.1',
          metadata: {
            toolName,
            findingsCount: findings.length,
            findingsTypes: Array.from(new Set(findings.map((f) => f.type))),
          },
          isDemo,
        });
      } catch (err) {
        console.error('[Security Engine] Failed to log DLP audit:', err);
      }
    }

    return {
      riskScore,
      decision,
      findings,
      originalText: rawText,
      redactedText: redacted,
      inspectedAt: new Date().toISOString(),
      sanitized: findings.length > 0,
    };
  },
};
