
/**
 * PostgreSQL Schema Migration Runner
 * Executes migrations and seeds initial required tables

 */
import 'dotenv/config';
import fs from 'fs';
import path from 'path';
import { dbQuery, testDbConnection, sanitizeDbError } from './pool';
import { seedInitialDatabaseData } from './seeds';

export interface MigrationResult {
  success: boolean;
  message: string;
  tablesCreated?: string[];
  durationMs: number;
}

export async function runMigrations(): Promise<MigrationResult> {
  const startTime = Date.now();
  console.log('[AgentGuard Migration] Checking database connection...');

  const dbStatus = await testDbConnection();
  if (dbStatus.state !== 'CONNECTED') {
    return {
      success: false,
      message: `Database not connected: ${dbStatus.error || 'Check DATABASE_URL'}`,
      durationMs: Date.now() - startTime,
    };
  }

  try {
    const migrationsDir = path.resolve(process.cwd(), 'migrations');
    if (!fs.existsSync(migrationsDir)) {
      throw new Error(`Migrations directory not found at ${migrationsDir}`);
    }

    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    for (const file of migrationFiles) {
      const filePath = path.join(migrationsDir, file);
      console.log(`[AgentGuard Migration] Executing ${file}...`);
      const sqlContent = fs.readFileSync(filePath, 'utf-8');
      await dbQuery(sqlContent);
    }

    // Verify all 5 core tables exist
    const tablesCheck = await dbQuery<{ table_name: string }>(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
        AND table_name IN ('security_policies', 'mcp_servers', 'tool_calls', 'threats', 'audit_logs', 'approval_requests')
    `);

    const existingTables = tablesCheck.rows.map((r) => r.table_name);
    console.log(`[AgentGuard Migration] Verified tables in PostgreSQL:`, existingTables);

    // Seed default baseline policies & servers if empty
    await seedInitialDatabaseData();

    const durationMs = Date.now() - startTime;
    return {
      success: true,
      message: `Successfully executed migrations in ${durationMs}ms. Verified ${existingTables.length} tables.`,
      tablesCreated: existingTables,
      durationMs,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown migration error';
    console.error('[AgentGuard Migration] Error executing schema migrations:', sanitizeDbError(msg));
    return {
      success: false,
      message: `Migration failed: ${sanitizeDbError(msg)}`,
      durationMs: Date.now() - startTime,
    };
  }
}

// Standalone execution entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  runMigrations()
    .then((res) => {
      console.log(res);
      process.exit(res.success ? 0 : 1);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
