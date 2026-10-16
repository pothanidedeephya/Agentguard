/**
 * AgentGuard Full-Stack Server
 * Express API Gateway + Vite Dev Middleware / Production Static Server
 */
import express from 'express';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import apiRouter from './src/server/routes/api';
import { safeErrorHandler } from './src/server/middleware/auth';
import { testDbConnection, getDbPool, closeDbPool } from './src/server/db/pool';
import { runMigrations } from './src/server/db/migrate';

dotenv.config();

// Parse port from CLI arguments or environment (default 3000)
function resolvePort(): number {
  const args = process.argv;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      const p = parseInt(args[i + 1], 10);
      if (!isNaN(p)) return p;
    }
    if (args[i].startsWith('--port=')) {
      const p = parseInt(args[i].split('=')[1], 10);
      if (!isNaN(p)) return p;
    }
  }
  return parseInt(process.env.PORT || '3000', 10);
}

const PORT = resolvePort();
const isProduction = process.env.NODE_ENV === 'production';

async function startServer() {
  const app = express();

  // JSON Body Parser with safe payload limit
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Mount API Gateway endpoints
  app.use(apiRouter);
  app.use(safeErrorHandler);

  // Initialize and verify Database connection if configured
  console.log('[AgentGuard] Starting runtime gateway on port', PORT);
  if (process.env.DATABASE_URL) {
    console.log('[AgentGuard] DATABASE_URL detected. Testing PostgreSQL connection...');
    testDbConnection()
      .then(async (status) => {
        if (status.state === 'CONNECTED') {
          console.log(`[AgentGuard] Connected to PostgreSQL on ${status.host} (${status.database})`);
          console.log('[AgentGuard] Checking and applying migrations...');
          const migResult = await runMigrations();
          console.log('[AgentGuard] Migration status:', migResult.message);
        } else {
          console.warn('[AgentGuard] PostgreSQL connection check failed:', status.error);
        }
      })
      .catch((err) => {
        console.warn('[AgentGuard] Database initialization error:', err.message);
      });
  } else {
    console.log('[AgentGuard] No DATABASE_URL set. Running in Local / Demo Mode (PostgreSQL features will report DISCONNECTED until configured).');
  }

  // Mount Frontend
  if (!isProduction) {
    // Dynamic import of Vite createServer in development
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
    console.log('[AgentGuard] Vite middleware mounted for development HMR & SPA serving.');
  } else {
    // Static production build serving
    const distPath = path.resolve(process.cwd(), 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
      console.log('[AgentGuard] Serving production assets from dist/');
    } else {
      console.warn('[AgentGuard] Production dist/ folder not found. Please run npm run build.');
    }
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AgentGuard] Server listening at http://0.0.0.0:${PORT}`);
  });

  const shutdown = async (signal: string) => {
    console.log(`[AgentGuard] Received ${signal}. Initiating graceful shutdown...`);
    server.close(async () => {
      console.log('[AgentGuard] HTTP listener closed.');
      await closeDbPool();
      console.log('[AgentGuard] Shutdown complete.');
      process.exit(0);
    });
    // Fallback timer if connections hang
    setTimeout(() => {
      console.error('[AgentGuard] Shutdown timed out after 10s. Forcing exit.');
      process.exit(1);
    }, 10000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

startServer().catch((err) => {
  console.error('[AgentGuard Fatal] Server failed to start:', err);
  process.exit(1);
});
