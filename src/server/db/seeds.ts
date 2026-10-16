/**
 * Default Seed Records for Security Policies and MCP Servers
 * Ensures clean initial state upon fresh database deployment
 */
import { dbQuery } from './pool';

export async function seedInitialDatabaseData(): Promise<void> {
  // Check if policies exist
  const policyCheck = await dbQuery('SELECT COUNT(*) as count FROM security_policies');
  if (parseInt(policyCheck.rows[0].count, 10) === 0) {
    console.log('[AgentGuard DB] Seeding default security policies into PostgreSQL...');
    const defaultPolicies = [
      {
        id: 'pol-001',
        name: 'Directory Traversal & Path Quarantine',
        description: 'Prohibits any relative path climbing (../ or ..\\) and unauthorized access outside sandbox paths.',
        rule_type: 'PARAMETER_INSPECTION',
        target_tools: JSON.stringify(['filesystem/read_file', 'filesystem/write_file', 'filesystem/list_directory']),
        target_servers: JSON.stringify(['filesystem-mcp']),
        risk_threshold: 85,
        action: 'BLOCK',
        author: 'sec-admin@agentguard.internal',
      },
      {
        id: 'pol-002',
        name: 'Arbitrary Shell Execution Quarantine',
        description: 'Restricts shell commands. Unsandboxed bash or powershell execution requires immediate blocking or elevated authorization.',
        rule_type: 'TOOL_RESTRICTION',
        target_tools: JSON.stringify(['shell/exec', 'terminal/run_command', 'process/spawn']),
        target_servers: JSON.stringify(['shell-exec-mcp']),
        risk_threshold: 90,
        action: 'BLOCK',
        author: 'sec-admin@agentguard.internal',
      },
      {
        id: 'pol-003',
        name: 'Database Destructive DDL Guard',
        description: 'Intercepts SQL DROP, TRUNCATE, and ALTER commands targeting production schemas and halts for human security review.',
        rule_type: 'RISK_THRESHOLD',
        target_tools: JSON.stringify(['database/execute_query', 'postgres/query', 'mysql/query']),
        target_servers: JSON.stringify(['postgres-mcp']),
        risk_threshold: 75,
        action: 'REQUIRE_APPROVAL',
        author: 'analyst-dave@agentguard.internal',
      },
      {
        id: 'pol-004',
        name: 'Response Data Loss Prevention (DLP) & Secret Scrub',
        description: 'Scans outbound tool responses for leaked cloud credentials, API tokens, and customer PII before passing to agent context.',
        rule_type: 'RESPONSE_DLP',
        target_tools: JSON.stringify(['*']),
        target_servers: JSON.stringify(['*']),
        risk_threshold: 60,
        action: 'REDACT',
        author: 'sec-admin@agentguard.internal',
      },
      {
        id: 'pol-005',
        name: 'Indirect Prompt Injection Sentinel',
        description: 'Inspects tool outputs from external sources (web scraping, email, search) for jailbreak directives and overrides.',
        rule_type: 'PROMPT_SAFETY',
        target_tools: JSON.stringify(['web_search/scrape', 'email/fetch_body', 'browser/navigate']),
        target_servers: JSON.stringify(['web-search-mcp']),
        risk_threshold: 80,
        action: 'BLOCK',
        author: 'analyst-claire@agentguard.internal',
      },
    ];

    for (const p of defaultPolicies) {
      await dbQuery(
        `INSERT INTO security_policies 
         (id, name, description, rule_type, target_tools, target_servers, risk_threshold, action, author, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, true, NOW(), NOW())
         ON CONFLICT (id) DO NOTHING`,
        [p.id, p.name, p.description, p.rule_type, p.target_tools, p.target_servers, p.risk_threshold, p.action, p.author]
      );
    }
  }

}



