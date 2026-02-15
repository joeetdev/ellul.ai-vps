/**
 * Caddyfile Generator
 *
 * Generates complete Caddyfile content as a pure string.
 * No shell wrappers, no placeholders — ready to write to disk.
 *
 * This is the single source of truth for Caddy configuration.
 * Used by:
 * - Provisioning (caddy.ts wraps this in shell for cloud-init)
 * - Runtime (ellulai-caddy-gen CLI for deployment model switches)
 */

import { generateCaddyHandlers } from "./handlers";

export interface CaddyfileOptions {
  deploymentModel: "cloudflare" | "direct" | "gateway";
  mainDomain: string;
  codeDomain: string;
  devDomain: string;
}

interface TlsConfig {
  cert: string;
  key: string;
  clientAuth?: string;
}

interface SiteBlock {
  addresses: string[];
  tls?: TlsConfig | "internal";
  handlers: string;
}

function renderTls(tls: TlsConfig | "internal"): string {
  if (tls === "internal") return "    tls internal";
  const lines = [`    tls ${tls.cert} ${tls.key}`];
  if (tls.clientAuth) {
    lines[0] += " {";
    lines.push("        client_auth {");
    lines.push("            mode require_and_verify");
    lines.push(`            trusted_ca_cert_file ${tls.clientAuth}`);
    lines.push("        }");
    lines.push("    }");
  }
  return lines.join("\n");
}

function renderSiteBlock(site: SiteBlock): string {
  const addr = site.addresses.join(", ");
  const parts = [addr + " {"];
  if (site.tls) parts.push(renderTls(site.tls));
  parts.push("");
  parts.push(site.handlers);
  parts.push("}");
  return parts.join("\n");
}

function renderGlobalOptions(autoHttps: boolean): string {
  const lines = ["{"];
  if (!autoHttps) lines.push("    auto_https off");
  lines.push("    email admin@ellul.ai");
  lines.push("}");
  return lines.join("\n");
}

function replaceDomains(text: string, main: string, code: string, dev: string): string {
  return text
    .replace(/MAIN_DOMAIN/g, main)
    .replace(/CODE_DOMAIN_PLACEHOLDER/g, code)
    .replace(/DEV_DOMAIN_PLACEHOLDER/g, dev);
}

const CF_AOP_CA = "/etc/caddy/cf-origin-pull-ca.pem";

/**
 * Generate a complete Caddyfile as a pure string.
 */
export function generateCaddyfileContent(opts: CaddyfileOptions): string {
  const { deploymentModel, mainDomain, codeDomain, devDomain } = opts;
  const replace = (text: string) => replaceDomains(text, mainDomain, codeDomain, devDomain);

  const sites: SiteBlock[] = [];

  if (deploymentModel === "direct") {
    // Single site block, all domains, Let's Encrypt ACME
    sites.push({
      addresses: [mainDomain, codeDomain, devDomain],
      handlers: replace(generateCaddyHandlers("all")),
    });
  } else {
    // Two site blocks: ai (srv + code) and app (dev preview)
    const aiTls: SiteBlock["tls"] =
      deploymentModel === "cloudflare"
        ? { cert: "/etc/caddy/origin.crt", key: "/etc/caddy/origin.key", clientAuth: CF_AOP_CA }
        : "internal";
    const appTls: SiteBlock["tls"] =
      deploymentModel === "cloudflare"
        ? { cert: "/etc/caddy/origin-app.crt", key: "/etc/caddy/origin-app.key", clientAuth: CF_AOP_CA }
        : "internal";

    sites.push({
      addresses: [`${mainDomain}:443`, `${codeDomain}:443`],
      tls: aiTls,
      handlers: replace(generateCaddyHandlers("ai")),
    });
    sites.push({
      addresses: [`${devDomain}:443`],
      tls: appTls,
      handlers: replace(generateCaddyHandlers("app")),
    });
  }

  const parts = [
    renderGlobalOptions(deploymentModel === "direct"),
    "",
    "import /etc/caddy/sites-enabled/*.caddy",
    "",
    ...sites.map(renderSiteBlock),
    "",
  ];

  return parts.join("\n");
}
