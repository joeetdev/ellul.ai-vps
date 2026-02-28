/**
 * AI Model Waterfall Configuration
 *
 * Free models are auto-discovered from OpenCode Zen's /models endpoint
 * (in ai-proxy.ts). This file only defines the paid safety net.
 *
 * Architecture:
 *   1. [Auto-discovered free models from Zen — refreshed every 30 min]
 *   2. DeepSeek V3 — paid safety net (~$0.30/1M)
 *
 * API Endpoints:
 *   - OpenCode Zen: https://opencode.ai/zen/v1/chat/completions
 *   - DeepSeek: https://api.deepseek.com/v1/chat/completions
 *
 * Required Environment Variables:
 *   - OPENCODE_API_KEY: For Zen free models
 *   - DEEPSEEK_API_KEY: For paid fallback
 */

export interface WaterfallModelConfig {
  id: string;
  name: string;
  provider: "opencode" | "deepseek" | "openrouter" | "anthropic" | "openai" | "google";
  modelId: string;
  baseUrl: string;
  isPaid: boolean;
  description: string;
  format?: "anthropic";
}

// ─── BYOK Provider Detection & Configs ──────────────────────────────

export type ByokProvider = "anthropic" | "openai" | "openrouter" | "google";

export interface ByokProviderConfig {
  name: string;
  baseUrl: string;
  modelId: string;
  modelName: string;
  format: "openai" | "anthropic";
  authHeader: "bearer" | "x-api-key";
  extraHeaders?: Record<string, string>;
}

export const BYOK_PROVIDER_CONFIGS: Record<ByokProvider, ByokProviderConfig> = {
  anthropic: {
    name: "Anthropic",
    baseUrl: "https://api.anthropic.com/v1",
    modelId: "claude-sonnet-4-20250514",
    modelName: "Claude Sonnet 4",
    format: "anthropic",
    authHeader: "x-api-key",
    extraHeaders: { "anthropic-version": "2023-06-01" },
  },
  openai: {
    name: "OpenAI",
    baseUrl: "https://api.openai.com/v1",
    modelId: "gpt-4o",
    modelName: "GPT-4o",
    format: "openai",
    authHeader: "bearer",
  },
  openrouter: {
    name: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    modelId: "anthropic/claude-sonnet-4-20250514",
    modelName: "Claude Sonnet 4",
    format: "openai",
    authHeader: "bearer",
  },
  google: {
    name: "Google",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    modelId: "gemini-2.5-flash",
    modelName: "Gemini 2.5 Flash",
    format: "openai",
    authHeader: "bearer",
  },
};

/**
 * Auto-detect BYOK provider from API key prefix.
 * Rejects empty/short keys with an error.
 */
export function detectKeyProvider(key: string): ByokProvider {
  const trimmed = key.trim();
  if (!trimmed || trimmed.length < 10) {
    throw new Error("API key must be at least 10 characters");
  }

  if (trimmed.startsWith("sk-ant-")) return "anthropic";
  if (trimmed.startsWith("sk-or-")) return "openrouter";
  if (trimmed.startsWith("sk-")) return "openai";
  if (trimmed.startsWith("AIza")) return "google";

  // Default fallback — OpenRouter accepts any model ID
  return "openrouter";
}

/**
 * THE WATERFALL: Paid safety net only.
 * Free models are auto-discovered from Zen in ai-proxy.ts.
 */
export const WATERFALL_MODELS: WaterfallModelConfig[] = [
  {
    id: "paid-deepseek",
    name: "DeepSeek V3",
    provider: "deepseek",
    modelId: "deepseek-chat",
    baseUrl: "https://api.deepseek.com/v1",
    isPaid: true,
    description: "Paid safety net (~$0.30/1M) - Always reliable",
  },
];

export const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

/**
 * Get the API key for a given provider
 */
export function getProviderApiKey(provider: string): string | undefined {
  if (provider === "deepseek") {
    return process.env.DEEPSEEK_API_KEY;
  }
  if (provider === "openrouter") {
    return undefined; // OpenRouter keys are per-request (user's own key from DB)
  }
  return process.env.OPENCODE_API_KEY;
}

/**
 * Check if a model is paid (requires rate limiting)
 */
export function isPaidModel(modelConfig: WaterfallModelConfig): boolean {
  return modelConfig.isPaid;
}

/**
 * Get all available models for the /models endpoint
 */
export function getAvailableModels(): WaterfallModelConfig[] {
  return WATERFALL_MODELS;
}

/**
 * Check if we have the required API key for a model
 */
export function hasRequiredApiKey(modelConfig: WaterfallModelConfig): boolean {
  const apiKey = getProviderApiKey(modelConfig.provider);
  return !!apiKey;
}

/**
 * Get only the paid models (for rate limiting display)
 */
export function getPaidModels(): WaterfallModelConfig[] {
  return WATERFALL_MODELS.filter((m) => m.isPaid);
}

/**
 * Get only the free models
 */
export function getFreeModels(): WaterfallModelConfig[] {
  return WATERFALL_MODELS.filter((m) => !m.isPaid);
}

/**
 * Get the primary model (first free model in the waterfall).
 * Used as the default model for OpenCode and other AI tool configs.
 */
export function getPrimaryModel(): WaterfallModelConfig {
  return WATERFALL_MODELS.find((m) => !m.isPaid)! || WATERFALL_MODELS[0]!;
}

/**
 * Generate the OpenClaw config JSON for a server.
 * Configures the gateway, auth token, and ellulai provider
 * so OpenClaw can route requests through the ellul.ai AI proxy.
 *
 * IMPORTANT: This config is baked into the VPS at provisioning time and never
 * updates. We use a stable "default" model ID — the AI proxy ignores it and
 * runs the full waterfall regardless. This means we can swap free models in
 * the proxy without re-provisioning any servers.
 */
export function getOpenclawConfigJson(apiUrl: string, aiProxyToken: string): string {
  return JSON.stringify(
    {
      commands: { native: "auto", nativeSkills: "auto" },
      gateway: {
        mode: "local",
        auth: { mode: "token", token: aiProxyToken },
        http: { endpoints: { chatCompletions: { enabled: true } } },
      },
      agents: {
        defaults: {
          model: { primary: "ellulai/default" },
        },
      },
      models: {
        mode: "merge",
        providers: {
          ellulai: {
            baseUrl: `${apiUrl}/api/ai`,
            apiKey: aiProxyToken,
            api: "openai-completions",
            models: [
              { id: "default", name: "ellul.ai AI", reasoning: false, input: ["text"] },
            ],
          },
        },
      },
    },
    null,
    2
  );
}

/**
 * Heuristic quality score for a model ID. Higher = better.
 * Version numbers aren't comparable across families (glm-5 ≠ better than minimax-m2.5),
 * so we just check presence of a version as a quality signal. Among equal scores,
 * the Zen API order is preserved (stable sort) as the tiebreaker.
 */
function modelQualityScore(id: string): number {
  let score = /\d/.test(id) ? 1 : 0; // versioned models above unversioned
  if (/large/i.test(id)) score += 0.3;
  if (/mini|nano|small/i.test(id)) score -= 1;
  return score;
}

/**
 * Discover the best free model from OpenCode's Zen endpoint.
 * All Zen models are treated as free — no hardcoded model names.
 * Picks the highest-quality model by version number heuristic.
 * Returns the opencode/ prefixed model ID, or null if discovery fails.
 */
async function discoverBestZenModel(): Promise<string | null> {
  try {
    const res = await fetch("https://opencode.ai/zen/v1/models", {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { data?: { id: string }[] };
    const models = data.data || [];
    if (models.length === 0) return null;
    // Sort by quality heuristic — highest version number wins
    models.sort((a, b) => modelQualityScore(b.id) - modelQualityScore(a.id));
    return `opencode/${models[0]!.id}`;
  } catch {
    return null;
  }
}

/**
 * Generate the OpenCode config JSON for a server.
 *
 * Fetches the best free model from OpenCode's Zen endpoint at provisioning time.
 * The agent bridge's zen-models service will continue auto-discovering and
 * switching to the best available model at runtime.
 */
export async function getOpencodeConfigJson(): Promise<string> {
  // Discover best free model with retries. If we write a null model,
  // OpenCode falls back to its built-in default (e.g. claude-opus)
  // which isn't free and will fail without API keys.
  let model: string | null = null;
  for (let attempt = 0; attempt < 3 && !model; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, 2000));
    model = await discoverBestZenModel();
  }
  if (!model) {
    console.warn('[ai-config] Zen discovery failed after 3 attempts — config will have no model, runtime zen refresh will handle it');
  }
  return JSON.stringify(
    {
      $schema: "https://opencode.ai/config.json",
      ...(model ? { model } : {}),
    },
    null,
    2
  );
}
