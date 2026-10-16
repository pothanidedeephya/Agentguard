/**
 * PostgreSQL Connection Pool & Lifecycle Manager
 * Handles connection pooling, health checks, and secure querying
 */
import pg from 'pg';

const { Pool } = pg;

export interface DatabaseStatus {
  state: 'CONNECTED' | 'DISCONNECTED' | 'NOT_CONFIGURED';
  lastChecked: string;
  error?: string;
  host?: string;
  database?: string;
  poolSize?: number;
  activeClients?: number;
}

let pool: pg.Pool | null = null;
let currentStatus: DatabaseStatus = {
  state: 'NOT_CONFIGURED',
  lastChecked: new Date().toISOString(),
};

/**
 * Initializes or retrieves the PostgreSQL connection pool
 */
export function getDbPool(): pg.Pool | null {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString || connectionString.trim() === '') {
    currentStatus = {
      state: 'NOT_CONFIGURED',
      lastChecked: new Date().toISOString(),
      error: 'DATABASE_URL environment variable is not configured',
    };
    return null;
  }

  if (pool) {
    return pool;
  }

  try {
    const isLocalhost = connectionString.includes('localhost') || connectionString.includes('127.0.0.1');

    pool = new Pool({
      connectionString,
      // Supabase and hosted cloud PostgreSQL require SSL
      ssl: isLocalhost ? false : { rejectUnauthorized: false },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });

    pool.on('error', (err) => {
      console.error('[AgentGuard DB Pool] Unexpected client error:', err.message);
      currentStatus = {
        state: 'DISCONNECTED',
        lastChecked: new Date().toISOString(),
        error: sanitizeDbError(err.message),
      };
    });

    return pool;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown pool creation error';
    currentStatus = {
      state: 'DISCONNECTED',
      lastChecked: new Date().toISOString(),
      error: sanitizeDbError(msg),
    };
    return null;
  }
}

/**
 * Verifies the database connection with a lightweight health query
 */
export async function testDbConnection(overrideUrl?: string): Promise<DatabaseStatus> {
  const urlToTest = overrideUrl !== undefined ? overrideUrl : process.env.DATABASE_URL;

  if (!urlToTest || urlToTest.trim() === '') {
    currentStatus = {
      state: 'NOT_CONFIGURED',
      lastChecked: new Date().toISOString(),
      error: 'DATABASE_URL environment variable is not set.',
    };
    return currentStatus;
  }

  let testPool: pg.Pool;
  let shouldClose = false;

  if (overrideUrl) {
    const isLocalhost = overrideUrl.includes('localhost') || overrideUrl.includes('127.0.0.1');
    testPool = new Pool({
      connectionString: overrideUrl,
      ssl: isLocalhost ? false : { rejectUnauthorized: false },
      connectionTimeoutMillis: 5000,
    });
    shouldClose = true;
  } else {
    const p = getDbPool();
    if (!p) return currentStatus;
    testPool = p;
  }

  try {
    const client = await testPool.connect();
    try {
      const res = await client.query('SELECT 1 as ping, current_database() as db_name, current_user as db_user, version()');
      const dbName = res.rows[0]?.db_name || 'postgres';

      let parsedHost = 'remote-host';
      try {
        const parsed = new URL(urlToTest);
        parsedHost = parsed.hostname;
      } catch {
        // ignore parse
      }

      currentStatus = {
        state: 'CONNECTED',
        lastChecked: new Date().toISOString(),
        host: parsedHost,
        database: dbName,
        poolSize: testPool.totalCount,
        activeClients: testPool.waitingCount,
      };

      return currentStatus;
    } finally {
      client.release();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Connection failed';
    currentStatus = {
      state: 'DISCONNECTED',
      lastChecked: new Date().toISOString(),
      error: sanitizeDbError(msg),
    };
    return currentStatus;
  } finally {
    if (shouldClose) {
      await testPool.end().catch(() => {});
    }
  }
}

/**
 * Helper to execute parameterized SQL queries safely
 */
export async function dbQuery<T extends pg.QueryResultRow = any>(
  text: string,
  params: any[] = []
): Promise<pg.QueryResult<T>> {
  const p = getDbPool();
  if (!p) {
    throw new Error('Database pool unavailable. Check DATABASE_URL configuration.');
  }
  return p.query<T>(text, params);
}

/**
 * Strips password and sensitive credentials from error messages
 */
export function sanitizeDbError(errorText: string): string {
  return errorText
    .replace(/:\/\/[^:]+:[^@]+@/, '://***:***@')
    .replace(/password=[^\s]+/gi, 'password=***');
}

export function getCachedDatabaseStatus(): DatabaseStatus {
  return currentStatus;
}

/**
 * Closes the database connection pool gracefully during process termination
 */
export async function closeDbPool(): Promise<void> {
  if (pool) {
    try {
      await pool.end();
      pool = null;
      currentStatus = {
        state: 'DISCONNECTED',
        lastChecked: new Date().toISOString(),
      };
      console.log('[AgentGuard DB Pool] Pool closed successfully.');
    } catch (err: unknown) {
      console.error('[AgentGuard DB Pool] Error closing pool:', err);
    }
  }
}

