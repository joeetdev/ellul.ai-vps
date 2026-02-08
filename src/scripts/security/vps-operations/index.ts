/**
 * VPS Operations - SSH Only tier terminal scripts
 *
 * Each script calls the platform API with the AI proxy token,
 * proving SSH access for operations that are blocked via the web dashboard.
 */
export { getDeleteScript } from "./delete";
export { getRebuildScript } from "./rebuild";
export { getRollbackScript } from "./rollback";
export { getChangeTierScript } from "./change-tier";
export { getSettingsScript } from "./settings";
export { getDeploymentScript } from "./deployment";
