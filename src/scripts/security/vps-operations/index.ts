/**
 * VPS Operations - CLI scripts installed on each VPS.
 *
 * Each script calls the platform API with the AI proxy token.
 * Standard and Web Locked tiers are directed to use the dashboard instead.
 */
export { getDeleteScript } from "./delete";
export { getRebuildScript } from "./rebuild";
export { getRollbackScript } from "./rollback";
export { getChangeTierScript } from "./change-tier";
export { getSettingsScript } from "./settings";
export { getDeploymentScript } from "./deployment";
