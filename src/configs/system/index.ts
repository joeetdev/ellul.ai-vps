/**
 * System Configuration Generators
 *
 * Core system configurations: bash, git, SSH, security.
 */

export { getGlobalGitignore } from "./gitignore";
export { getPreCommitHook } from "./pre-commit-hook";
export {
  getSshHardeningConfig,
  getFail2banConfig,
  getUnattendedUpgradesConfig,
  getAutoUpgradesConfig,
} from "./ssh-hardening";
export { getBashrcConfig, getMotdScript } from "./bashrc";
