/**
 * AI Model Waterfall Configuration
 *
 * Sophisticated "Waterfall Fallback" strategy for high-reliability AI.
 * Aggressively hunts for free compute before falling back to paid.
 *
 * Uses only OpenAI-compatible /chat/completions endpoints.
 *
 * The Logic Flow (free models tried first, paid as safety net):
 *   1. MiniMax M2.5 Free          - Strong general purpose (Free)
 *   2. Big Pickle (big-pickle)    - General purpose (Free)
 *   3. GPT 5 Nano (gpt-5-nano)   - Lightweight GPT (Free)
 *   4. DeepSeek V3                - Paid safety net (~$0.30/1M)
 *
 * Free model list synced from: https://opencode.ai/docs/zen/
 *
 * API Endpoints:
 *   - OpenCode: https://opencode.ai/zen/v1/chat/completions
 *   - DeepSeek: https://api.deepseek.com/v1/chat/completions
 *
 * Required Environment Variables:
 *   - OPENCODE_API_KEY: For free tier models (1-3)
 *   - DEEPSEEK_API_KEY: For paid fallback (4)
 */

export interface WaterfallModelConfig {
  id: string;
  name: string;
  provider: "opencode" | "deepseek";
  modelId: string;
  baseUrl: string;
  isPaid: boolean;
  description: string;
}

/**
 * THE WATERFALL: Order matters! Top is tried first.
 * Only coding-capable models with OpenAI-compatible /chat/completions endpoint.
 *
 * OpenCode API: https://opencode.ai/zen/v1/chat/completions
 * DeepSeek API: https://api.deepseek.com/v1/chat/completions
 */
export const WATERFALL_MODELS: WaterfallModelConfig[] = [
  // === FREE TIER (OpenCode Zen) - synced from https://opencode.ai/docs/zen/ ===
  {
    id: "free-minimax",
    name: "MiniMax M2.5",
    provider: "opencode",
    modelId: "minimax-m2.5-free",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - Strong general purpose",
  },
  {
    id: "free-pickle",
    name: "Big Pickle",
    provider: "opencode",
    modelId: "big-pickle",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - General purpose",
  },
  {
    id: "free-gpt-nano",
    name: "GPT 5 Nano",
    provider: "opencode",
    modelId: "gpt-5-nano",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - Lightweight GPT",
  },
  // === PAID SAFETY NET (DeepSeek) - Last resort ===
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

/**
 * Get the API key for a given provider
 */
export function getProviderApiKey(provider: "opencode" | "deepseek"): string | undefined {
  if (provider === "deepseek") {
    return process.env.DEEPSEEK_API_KEY;
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
 * Generate the OpenCode config JSON for a server.
 *
 * Same as OpenClaw — uses a stable "default" model ID. The AI proxy's
 * waterfall handles actual model selection, so this config never goes stale.
 */
export function getOpencodeConfigJson(apiUrl: string, aiProxyToken: string): string {
  return JSON.stringify(
    {
      $schema: "https://opencode.ai/config.json",
      model: "ellulai/default",
      provider: {
        ellulai: {
          npm: "@ai-sdk/openai-compatible",
          name: "ellul.ai AI",
          options: {
            baseURL: `${apiUrl}/api/ai`,
            apiKey: aiProxyToken,
          },
          models: {
            default: {
              name: "ellul.ai AI",
              maxTokens: 16384,
            },
          },
        },
      },
    },
    null,
    2
  );
}
