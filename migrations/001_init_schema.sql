-- ==============================================================================
-- AgentGuard MCP Runtime Security - Database Schema Migration
-- Target: PostgreSQL / Supabase
-- ==============================================================================

-- 1. Table: security_policies
CREATE TABLE IF NOT EXISTS security_policies (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rule_type VARCHAR(64) NOT NULL,
    target_tools JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    target_servers JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    risk_threshold INTEGER NOT NULL DEFAULT 80 CHECK (risk_threshold >= 0 AND risk_threshold <= 100),
    action VARCHAR(32) NOT NULL CHECK (action IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL', 'REDACT')),
    author VARCHAR(255) NOT NULL DEFAULT 'system',
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Table: mcp_servers
CREATE TABLE IF NOT EXISTS mcp_servers (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    transport VARCHAR(32) NOT NULL CHECK (transport IN ('stdio', 'sse', 'websocket', 'http')),
    endpoint_or_command TEXT NOT NULL,
    connection_status VARCHAR(32) NOT NULL DEFAULT 'CONNECTED' CHECK (connection_status IN ('CONNECTED', 'DEGRADED', 'DISCONNECTED')),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_tools JSONB NOT NULL DEFAULT '[]'::jsonb,
    configured_env_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_calls_count INTEGER NOT NULL DEFAULT 0,
    blocked_calls_count INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER NOT NULL DEFAULT 15,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Table: tool_calls
CREATE TABLE IF NOT EXISTS tool_calls (
    id SERIAL PRIMARY KEY,
    call_id VARCHAR(64) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_id VARCHAR(128) NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    server_id VARCHAR(64) REFERENCES mcp_servers(id) ON DELETE SET NULL,
    server_name VARCHAR(255) NOT NULL,
    tool_name VARCHAR(255) NOT NULL,
    input_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    sanitized_input JSONB,
    normalized_params JSONB,
    input_summary TEXT,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL', 'REDACT')),
    execution_status VARCHAR(32) NOT NULL CHECK (execution_status IN ('EXECUTED', 'BLOCKED', 'FLAGGED_POST_EXEC', 'PENDING_APPROVAL', 'REJECTED')),
    duration_ms INTEGER NOT NULL DEFAULT 0,
    detection_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    output_data JSONB,
    redacted_output JSONB,
    audit_id VARCHAR(64),
    executed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_demo BOOLEAN NOT NULL DEFAULT FALSE
);

-- 4. Table: threats
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    threat_id VARCHAR(64) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tool_call_id VARCHAR(64) REFERENCES tool_calls(call_id) ON DELETE CASCADE,
    threat_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    source_tool VARCHAR(255) NOT NULL,
    server_name VARCHAR(255) NOT NULL,
    agent_name VARCHAR(255) NOT NULL,
    evidence TEXT NOT NULL,
    detection_rule VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INVESTIGATING', 'MITIGATED', 'FALSE_POSITIVE')),
    remediation TEXT,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE
);

-- 5. Table: audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    audit_id VARCHAR(64) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(255) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    tool_call_id VARCHAR(64),
    decision VARCHAR(32),
    risk_score INTEGER,
    reason TEXT NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    ip_address VARCHAR(64),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE
);

-- 6. Table: approval_requests
CREATE TABLE IF NOT EXISTS approval_requests (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    tool_call_id VARCHAR(64) NOT NULL REFERENCES tool_calls(call_id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    agent_name VARCHAR(255) NOT NULL,
    server_name VARCHAR(255) NOT NULL,
    tool_name VARCHAR(255) NOT NULL,
    input_params JSONB NOT NULL,
    risk_score INTEGER NOT NULL,
    policy_reason TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    reviewer VARCHAR(255),
    reviewed_at TIMESTAMPTZ,
    analyst_notes TEXT,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE
);

-- Indexes for performant filtering, sorting, and analytics
CREATE INDEX IF NOT EXISTS idx_tool_calls_timestamp ON tool_calls(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_decision ON tool_calls(decision);
CREATE INDEX IF NOT EXISTS idx_tool_calls_agent ON tool_calls(agent_name);
CREATE INDEX IF NOT EXISTS idx_tool_calls_server ON tool_calls(server_name);
CREATE INDEX IF NOT EXISTS idx_tool_calls_is_demo ON tool_calls(is_demo);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_call_id ON threats(tool_call_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
CREATE INDEX IF NOT EXISTS idx_approvals_call_id ON approval_requests(tool_call_id);
