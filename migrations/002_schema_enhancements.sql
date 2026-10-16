-- ==============================================================================
-- AgentGuard MCP Runtime Security - Migration 002: Schema Enhancements
-- Safe, repeatable column migrations for MCP Gateway auditability
-- ==============================================================================

-- 1. Enhance mcp_servers
ALTER TABLE mcp_servers 
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 2. Enhance tool_calls
ALTER TABLE tool_calls 
    ADD COLUMN IF NOT EXISTS sanitized_input JSONB,
    ADD COLUMN IF NOT EXISTS executed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 3. Enhance security_policies
ALTER TABLE security_policies 
    ADD COLUMN IF NOT EXISTS configuration JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 4. Enhance audit_logs
ALTER TABLE audit_logs 
    ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 5. Additional index optimizations for high-throughput MCP telemetry
CREATE INDEX IF NOT EXISTS idx_tool_calls_executed_at ON tool_calls(executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_calls_created_at ON tool_calls(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor);
