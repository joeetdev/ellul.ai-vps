/**
 * Routes Module Index
 *
 * Sovereign Shield handles 58 endpoints organized into these route modules:
 *
 * - health.routes.ts      - /health
 * - capabilities.routes.ts - /_auth/capabilities (version & feature discovery)
 * - session.routes.ts     - Forward auth & session management
 * - token.routes.ts       - Token authorization for services
 * - audit.routes.ts       - Audit log access & integrity verification
 * - tier.routes.ts        - Security tier management
 * - keys.routes.ts        - SSH key management
 * - login.routes.ts       - Passkey login
 * - setup.routes.ts       - Initial setup & registration
 * - bridge.routes.ts      - Platform bridge API
 * - recovery.routes.ts    - Recovery system
 * - confirm.routes.ts     - Operation confirmation
 * - upgrade.routes.ts     - Tier upgrades via JWT (Standard tier)
 * - secrets.routes.ts     - Encrypted environment secrets management
 * - static.routes.ts      - Static assets
 * - workflow.routes.ts    - Privileged workflow commands (expose, etc.)
 */

import type { Hono } from 'hono';
import { registerHealthRoutes } from './health.routes';
import { registerCapabilitiesRoutes } from './capabilities.routes';
import { registerSessionRoutes } from './session.routes';
import { registerTokenRoutes } from './token.routes';
import { registerAuditRoutes } from './audit.routes';
import { registerTierRoutes } from './tier.routes';
import { registerKeysRoutes } from './keys.routes';
import { registerLoginRoutes } from './login.routes';
import { registerSetupRoutes } from './setup.routes';
import { registerBridgeRoutes } from './bridge.routes';
import { registerRecoveryRoutes } from './recovery.routes';
import { registerConfirmRoutes } from './confirm.routes';
import { registerUpgradeRoutes } from './upgrade.routes';
import { registerStaticRoutes } from './static.routes';
import { registerGitRoutes } from './git.routes';
import { registerWorkflowRoutes } from './workflow.routes';
import { registerPreviewRoutes } from './preview.routes';
import { registerSecretsRoutes } from './secrets.routes';
import { registerChatRoutes } from './chat.routes';

export interface RouteConfig {
  hostname: string;
  rpName: string;
}

/**
 * Register all routes on the Hono app
 */
export function registerAllRoutes(app: Hono, config: RouteConfig): void {
  // Health check (no auth required)
  registerHealthRoutes(app);

  // Capabilities discovery (no auth required)
  registerCapabilitiesRoutes(app);

  // Session management (forward auth, PoP binding)
  registerSessionRoutes(app, config.hostname);

  // Token authorization (terminal, code, agent)
  registerTokenRoutes(app);

  // Audit log access
  registerAuditRoutes(app);

  // Security tier management
  registerTierRoutes(app);

  // SSH key management
  registerKeysRoutes(app, config.hostname);

  // Passkey login
  registerLoginRoutes(app, config.hostname);

  // Initial setup & registration
  registerSetupRoutes(app, config.hostname);

  // Platform bridge API
  registerBridgeRoutes(app, config.hostname);

  // Recovery system
  registerRecoveryRoutes(app, config.hostname);

  // Operation confirmation
  registerConfirmRoutes(app);

  // Tier upgrades via JWT (Standard tier users)
  registerUpgradeRoutes(app, config.hostname);

  // Secrets management (encrypted env vars)
  registerSecretsRoutes(app);

  // Git link/unlink authorization
  registerGitRoutes(app);

  // Privileged workflow commands (expose, etc.)
  registerWorkflowRoutes(app);

  // Preview auth (cross-site dev domain token flow)
  registerPreviewRoutes(app, config.hostname);

  // Chat SPA (VPS-served iframe for SSH-equivalent security)
  registerChatRoutes(app);

  // Static assets
  registerStaticRoutes(app);
}

export {
  registerHealthRoutes,
  registerCapabilitiesRoutes,
  registerSessionRoutes,
  registerTokenRoutes,
  registerAuditRoutes,
  registerTierRoutes,
  registerKeysRoutes,
  registerLoginRoutes,
  registerSetupRoutes,
  registerBridgeRoutes,
  registerRecoveryRoutes,
  registerConfirmRoutes,
  registerUpgradeRoutes,
  registerStaticRoutes,
  registerGitRoutes,
  registerWorkflowRoutes,
  registerPreviewRoutes,
  registerSecretsRoutes,
  registerChatRoutes,
};
