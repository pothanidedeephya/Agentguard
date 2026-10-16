# AgentGuard Backend — Runtime Defence for MCP-Connected AI Tools

AgentGuard is a high-performance runtime application security gateway designed specifically for Model Context Protocol (MCP) tool servers and autonomous AI agents. It acts as an authoritative security layer interposed between LLMs/AI Agents and downstream tool execution runtimes.

---

## 1. Architecture & Threat Model

```
+------------------+         +-------------------------------+         +-----------------------+
|                  |  HTTP   |     AgentGuard MCP Gateway    |  Exec   |  Downstream MCP Tool  |
|     AI Agent     | ------> |  - Auth & Zod Schema Valid.   | ------> |        Servers        |
| (Claude/OpenAI/  | <------ |  - Canonical Path Inspection  | <------ | - Filesystem MCP      |
| Autonomous Bot)  | Sanit.  |  - Dangerous Command Shield   | Output  | - PostgreSQL MCP      |
|                  | Result  |  - Policy Engine Matrix (DB)  |         | - GitHub MCP          |
+------------------+         |  - Human Approval Quarantine  |         | - Shell Exec MCP      |
                             |  - Downstream Execution Guard |         +-----------------------+
                             |  - Response DLP & Redaction   |
                             +---------------+---------------+
                                             |
                                    PostgreSQL / Supabase
                                    (Immutable Audit Logs,
                                     Telemetry, Policies)
```

### The Security Boundary
- **Authoritative Interposition**: Downstream MCP tool servers must reside in an isolated network perimeter accessible only via the AgentGuard gateway.
- **Fail-Closed Execution**: If any security policy is violated, traversal pattern is detected, or command injection sequence is identified, downstream tool execution is **strictly aborted**.
- **Human Approval Quarantine**: High-risk or destructive actions (such as `DROP TABLE` or destructive modifications) are quarantined in PostgreSQL and never executed prematurely.

---

## 2. The 12-Step MCP Runtime Security Pipeline

When a tool call enters `POST /api/mcp/gateway/call`:

1. **Request Ingestion**: Ingests tool call with agent ID, target server, tool name, and parameters.
2. **Identity Resolution**: Resolves agent credentials and target MCP server connection profile.
3. **Zod Schema Validation**: Enforces strict typing, preventing prototype pollution and malformed payloads.
4. **Authentication & Authorization**: Validates `AGENTGUARD_API_TOKEN` via Bearer or header tokens.
5. **Tool Allowlist Verification**: Confirms server availability and checks if the specific tool is active and allowed.
6. **Argument Inspection**:
   - Canonical path resolution against sandbox root (blocks `../`, null bytes, system directories like `/etc` or `C:\Windows`).
   - Command injection detection (blocks command chaining `&&`, `||`, `;`, pipes `|`, destructive binaries `rm -rf`, `curl | sh`).
   - Credential scrubbing from parameter values.
7. **Deterministic Risk Scoring**: Computes an explainable score from 0 to 100 with audit reasons.
8. **Policy Engine Evaluation**: Matches against active PostgreSQL `security_policies`.
9. **Decision Determination**: Assigns `ALLOW`, `BLOCK`, `REDACT`, or `REQUIRE_APPROVAL`.
10. **Execution Boundary**:
    - `BLOCK`: Halts immediately. Execution status = `BLOCKED`.
    - `REQUIRE_APPROVAL`: Halts immediately. Creates pending record in `approval_requests`.
    - `ALLOW` / `REDACT`: Sanitizes inputs and executes downstream tool.
11. **Response DLP & Output Inspection**: Scans output for API keys, SSNs, emails, phone numbers, and prompt injection markers. Redacts findings prior to agent return.
12. **Immutable Audit Persistence**: Persists tool call telemetry, detected threats, and audit logs with correlation IDs in PostgreSQL.

---

## 3. Database Schema (PostgreSQL / Supabase)

Migrations are located in `/migrations`:

- **`mcp_servers`**: Server metadata, transport protocol (`stdio`, `sse`, `websocket`, `http`), connection status, available tools, ping latency, and allowed/blocked counters.
- **`tool_calls`**: Complete telemetry with `call_id`, `agent_id`, `server_id`, `tool_name`, `input_params`, `sanitized_input`, `risk_score`, `decision`, `execution_status`, `detection_reasons`, `duration_ms`, `executed_at`, `created_at`.
- **`threats`**: Detailed security incident records with `threat_id`, `category`, `severity`, `risk_score`, `evidence`, `status`, and `remediation`.
- **`security_policies`**: Dynamic security policies with `rule_type`, `target_tools`, `target_servers`, `risk_threshold`, `action`, `configuration`, and `updated_at`.
- **`audit_logs`**: Append-only forensic audit trail with `actor`, `event_type`, `decision`, `risk_score`, `outcome`, `ip_address`, and `metadata`.
- **`approval_requests`**: Quarantine queue for human operator sign-off and resumption.

---

## 4. API Specification

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check distinguishing API operational state from Database state |
| `GET` | `/api/gateway/status` | Runtime gateway health, version, server count, and DB status |
| `POST` | `/api/mcp/gateway/call` | Primary 12-step MCP tool call execution & defense gateway |
| `POST` | `/api/evaluate` | Dry-run / standalone tool call policy evaluation |
| `POST` | `/api/inspect-response` | Standalone DLP & prompt injection response inspector |
| `GET` | `/api/overview` | Dashboard summary metrics and 24h trend percentages |
| `GET` | `/api/analytics/volume` | Time-series call volume aggregated by `15m`, `1h`, `24h`, or `7d` |
| `GET` | `/api/analytics/threats-breakdown` | Active threats categorized by threat vector |
| `GET` | `/api/analytics/risk-histogram` | Risk score distribution histogram across score buckets |
| `GET` | `/api/analytics/top-tools` | Most frequently invoked MCP tools and block ratios |
| `GET` | `/api/tool-calls` | Filterable, searchable tool call log trail |
| `GET` | `/api/tool-calls/:id` | Deep forensic details for a single tool call |
| `GET` | `/api/threats` | Active, investigating, and mitigated threat incidents |
| `PUT` | `/api/threats/:id/status` | Triage threat status (`ACTIVE`, `INVESTIGATING`, `MITIGATED`, `FALSE_POSITIVE`) |
| `GET` | `/api/policies` | Active and disabled security policy rules |
| `PUT` | `/api/policies` | Create or update a security policy rule in PostgreSQL |
| `GET` | `/api/mcp-servers` | Registry of connected MCP servers and tool configurations |
| `POST` | `/api/mcp-servers` | Register a new MCP server |
| `PUT` | `/api/mcp-servers/:id/tools/:toolName` | Toggle tool authorization on server allowlist |
| `POST` | `/api/mcp-servers/:id/ping` | Ping MCP server to measure latency |
| `GET` | `/api/approvals` | Pending, approved, and rejected human approval queue |
| `POST` | `/api/approvals/:id/decision` | Reviewer approval/rejection decision with optional resumption |
| `POST` | `/api/db/test-connection` | Verify PostgreSQL connection string |
| `POST` | `/api/db/run-migrations` | Execute schema migrations and seed initial records |

---

## 5. Environment Configuration

Configure variables in `.env`:

```bash
# PostgreSQL / Supabase connection URI (server-side only, never exposed to client)
DATABASE_URL="database"

# Server Port
PORT=3000

# Environment
NODE_ENV=development

# Optional server-side API token to protect privileged gateway endpoints
AGENTGUARD_API_TOKEN="my-secret-token"

# Frontend API base URL (empty for same-origin dev server)
VITE_API_BASE_URL=""
```

---

## 6. Verification & Automated Tests

Execute the automated test suite:

```bash
# Run 19 comprehensive tests
npm test

# Run TypeScript compile validation
npm run lint

# Run production build
npm run build
```
