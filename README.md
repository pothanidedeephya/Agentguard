# AgentGuard — MCP Runtime Security

**A policy-driven security gateway designed to protect AI agents and Model Context Protocol (MCP) servers.**

AgentGuard provides a security layer for inspecting AI-agent tool requests, detecting suspicious activity, evaluating risk, enforcing security policies, and maintaining an auditable record of security decisions.

## Architecture

AI Agent → AgentGuard Security Gateway → Security Policy Engine → MCP Server

The gateway is designed to validate requests, inspect tool parameters, evaluate security rules, and determine whether a request should be allowed, blocked, redacted, or require approval.

## Key Features

- **Runtime Security Evaluation:** Inspects tool-call parameters before downstream execution when requests pass through the gateway.
- **Threat Detection:** Detects configured suspicious patterns, including directory traversal and dangerous command sequences.
- **Risk Scoring:** Assigns risk scores to evaluated requests to support policy decisions.
- **Policy Enforcement:** Applies tool allowlists and configured security policies.
- **Threat Monitoring:** Displays security incidents, severity levels, and risk scores.
- **Audit Logging:** Records security decisions and related events for investigation and monitoring.
- **Data Protection:** Includes secret-detection and response-inspection logic designed to identify and redact sensitive information.
- **Security Dashboard:** Provides a unified interface for reviewing tool requests, threats, approval workflows, and audit records.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Node.js, TypeScript, Express |
| Request Validation | Zod |
| Security Engine | Custom rule-based detection and policy enforcement |
| Database | PostgreSQL through Supabase |
| Protocol | Model Context Protocol (MCP) |

## Prerequisites

- Node.js and npm
- A Supabase PostgreSQL database for persistent backend storage
- A Gemini API key only if the configured application features require Gemini

## Run Locally

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_PROJECT_DIRECTORY>
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create or update your local environment configuration using the variables required by the project.

For example:

```env
DATABASE_URL=your_postgresql_connection_string
GEMINI_API_KEY=your_gemini_api_key
```

Use the actual variable names required by your implementation. The Gemini key is optional if no enabled feature uses it.

**Security note:** Never commit real API keys, database credentials, or other secrets to GitHub. Keep local environment files private.

### 4. Run database migrations

If database migrations are configured in the project, run:

```bash
npm run db:migrate
```

### 5. Start the application

```bash
npm run dev
```

Open the local URL reported by the development server, typically:

```text
http://localhost:3000
```

## Security Evaluation

AgentGuard provides an evaluation endpoint for testing security decisions:

```text
POST /api/evaluate
```

Example path-traversal test:

```bash
curl -s -X POST http://localhost:3000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "srv-fs-01",
    "serverName": "Filesystem MCP",
    "toolName": "read_file",
    "parameters": {
      "path": "../../etc/passwd"
    }
  }'
```

In the tested configuration, this request produced a `BLOCK` decision with a risk score of `98` and a path-traversal finding.

**Note:** This evaluation endpoint operates in dry-run mode and does not execute the downstream MCP tool. Live MCP connectivity and enforcement should be verified separately before claiming end-to-end interception.

## Health and Monitoring

Health endpoint:

```text
GET /health
```

Gateway status endpoint:

```text
GET /api/gateway/status
```

These endpoints provide application health and gateway-status information.

## Project Goal

AgentGuard aims to make AI-agent tool interactions more controlled, observable, and auditable by placing policy-driven security checks between agents and the tools they access.

## Development Status

The local application, database connectivity, security evaluation endpoint, path-traversal blocking test, and dashboard audit views have been verified in the current development setup.

Real downstream MCP execution, authentication enforcement, and complete end-to-end gateway integration should be tested independently.

## License

Add the license applicable to this repository before distributing the project.
