/**
 * Security Middleware for AgentGuard Gateway
 * Handles API token authorization, correlation ID tracking, and safe error handling
 */
import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { sanitizeDbError } from '../db/pool';

export interface AuthenticatedRequest extends Request {
  correlationId?: string;
  authenticatedActor?: string;
}

/**
 * Attaches a correlation ID to every incoming request for immutable audit tracing
 */
export function correlationMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const incomingId = req.header('x-correlation-id') || req.header('x-request-id');
  const correlationId = incomingId && incomingId.length <= 64 
    ? incomingId 
    : `req-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;

  req.correlationId = correlationId;
  res.setHeader('x-correlation-id', correlationId);
  next();
}

/**
 * Verifies AGENTGUARD_API_TOKEN if set in environment
 * Allows public read-only and demo requests, but protects privileged mutation/execution endpoints
 */
export function requireGatewayAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const configuredToken = process.env.AGENTGUARD_API_TOKEN;

  // If no server-side token is configured, allow operation (local dev / demo mode)
  if (!configuredToken || configuredToken.trim() === '') {
    req.authenticatedActor = 'anonymous-operator';
    return next();
  }

  const authHeader = req.header('authorization');
  const tokenHeader = req.header('x-agentguard-token');

  let providedToken = '';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    providedToken = authHeader.slice(7).trim();
  } else if (tokenHeader) {
    providedToken = tokenHeader.trim();
  }

  // Timing-safe comparison to prevent side-channel timing attacks
  const tokenMatches = providedToken.length === configuredToken.length &&
    crypto.timingSafeEqual(Buffer.from(providedToken), Buffer.from(configuredToken));

  if (!tokenMatches) {
    res.status(401).json({
      error: 'Unauthorized: Invalid or missing AgentGuard API token.',
      code: 'AUTH_REQUIRED',
      correlationId: req.correlationId,
    });
    return;
  }

  req.authenticatedActor = 'authorized-mcp-gateway';
  next();
}

/**
 * Centralized safe error responder preventing disclosure of secrets or stack traces
 */
export function safeErrorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  const msg = err instanceof Error ? err.message : 'Internal Gateway Error';
  const cleanMsg = sanitizeDbError(msg);

  console.error(`[AgentGuard Error] ${req.method} ${req.path}:`, cleanMsg);

  res.status(500).json({
    error: 'An unexpected internal error occurred in the AgentGuard Gateway.',
    detail: process.env.NODE_ENV === 'development' ? cleanMsg : undefined,
    correlationId: (req as AuthenticatedRequest).correlationId,
  });
}
