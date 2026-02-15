/**
 * ellulai-caddy-gen CLI
 *
 * Generates a complete Caddyfile to stdout.
 * Called by the enforcer on deployment model switches.
 *
 * Usage:
 *   node /usr/local/bin/ellulai-caddy-gen \
 *     --model cloudflare \
 *     --main-domain abc12345-srv.ellul.ai \
 *     --code-domain abc12345-code.ellul.ai \
 *     --dev-domain abc12345-dev.ellul.app
 */

import { generateCaddyfileContent } from "./caddyfile";

function parseArgs(argv: string[]): Record<string, string> {
  const args: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("--") && i + 1 < argv.length) {
      args[arg.slice(2)] = argv[i + 1]!;
      i++;
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

const model = args["model"] as string | undefined;
const mainDomain = args["main-domain"] as string | undefined;
const codeDomain = args["code-domain"] as string | undefined;
const devDomain = args["dev-domain"] as string | undefined;

if (!model || !mainDomain || !codeDomain || !devDomain) {
  process.stderr.write(
    "Usage: ellulai-caddy-gen --model <cloudflare|direct|gateway> " +
    "--main-domain <domain> --code-domain <domain> --dev-domain <domain>\n"
  );
  process.exit(1);
}

if (model !== "cloudflare" && model !== "direct" && model !== "gateway") {
  process.stderr.write(`Invalid model: ${model}. Must be cloudflare, direct, or gateway.\n`);
  process.exit(1);
}

const content = generateCaddyfileContent({
  deploymentModel: model,
  mainDomain,
  codeDomain,
  devDomain,
});

process.stdout.write(content);
