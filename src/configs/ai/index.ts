/**
 * AI Model Waterfall Configuration
 *
 * Sophisticated "Waterfall Fallback" strategy for high-reliability AI.
 * Aggressively hunts for free compute before falling back to paid.
 *
 * Uses only OpenAI-compatible /chat/completions endpoints.
 *
 * The Logic Flow (free models tried first, paid as safety net):
 *   1. Kimi K2.5 Free             - Strong reasoning (Free)
 *   2. MiniMax M2.1 Free          - Recommended by OpenCode (Free)
 *   3. Grok Code (grok-code)      - Purpose-built for code (Free)
 *   4. GLM 4.7 Free               - Strong general purpose (Free)
 *   5. Big Pickle (big-pickle)    - General purpose (Free)
 *   6. GPT 5 Nano (gpt-5-nano)   - Lightweight GPT (Free)
 *   7. DeepSeek V3                - Paid safety net (~$0.30/1M)
 *
 * API Endpoints:
 *   - OpenCode: https://opencode.ai/zen/v1/chat/completions
 *   - DeepSeek: https://api.deepseek.com/v1/chat/completions
 *
 * Required Environment Variables:
 *   - OPENCODE_API_KEY: For free tier models (1-6)
 *   - DEEPSEEK_API_KEY: For paid fallback (7)
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
  // === FREE TIER (OpenCode) - OpenAI-compatible models ===
  {
    id: "free-kimi",
    name: "Kimi K2.5",
    provider: "opencode",
    modelId: "kimi-k2.5-free",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - Strong reasoning capabilities",
  },
  {
    id: "free-minimax",
    name: "MiniMax M2.1",
    provider: "opencode",
    modelId: "minimax-m2.1-free",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - Recommended by OpenCode",
  },
  {
    id: "free-grok",
    name: "Grok Code Fast 1",
    provider: "opencode",
    modelId: "grok-code",
    baseUrl: "https://opencode.ai/zen/v1",
    isPaid: false,
    description: "Free - Purpose-built for code",
  },
  {
    id: "free-glm",
    name: "GLM 4.7",
    provider: "opencode",
    modelId: "glm-4.7-free",
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
 * Generate the OpenCode config JSON for a server.
 * Uses the primary model from the waterfall as the configured model.
 * The proxy will still run the full waterfall regardless of what model
 * is configured here — this just tells OpenCode what to request.
 */
export function getOpencodeConfigJson(apiUrl: string, aiProxyToken: string): string {
  const model = getPrimaryModel();
  // Register ALL waterfall models so OpenCode knows about them when user switches
  const models: Record<string, { name: string; maxTokens: number }> = {};
  for (const m of WATERFALL_MODELS) {
    models[m.modelId] = {
      name: m.name,
      maxTokens: 16384,
    };
  }
  return JSON.stringify(
    {
      $schema: "https://opencode.ai/config.json",
      model: `ellulai/${model.modelId}`,
      provider: {
        ellulai: {
          npm: "@ai-sdk/openai-compatible",
          name: "ellul.ai AI",
          options: {
            baseURL: `${apiUrl}/api/ai`,
            apiKey: aiProxyToken,
          },
          models,
        },
      },
    },
    null,
    2
  );
}
