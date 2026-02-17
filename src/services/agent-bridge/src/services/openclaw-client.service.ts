/**
 * OpenClaw Client Service — HTTP Streaming API
 *
 * Connects to the local OpenClaw gateway via its OpenAI-compatible HTTP API.
 * Uses Server-Sent Events (SSE) for streaming responses.
 *
 * Each request is stateless — thread context is managed by the agent-bridge,
 * not by OpenClaw. The gateway auth token is read from the OpenClaw config.
 */

import { readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { REQUEST_TIMEOUT_MS } from "../config";

const OPENCLAW_PORT = 18790;
const OPENCLAW_HTTP_URL = `http://127.0.0.1:${OPENCLAW_PORT}`;

// ─── Types ──────────────────────────────────────────────

/** Callback for streaming response chunks */
type ChunkCallback = (chunk: OpenClawChunk) => void;

/** Parsed OpenClaw message types */
export interface OpenClawChunk {
  type: "text" | "tool_use" | "tool_result" | "file_edit" | "status" | "error";
  content?: string;
  tool?: string;
  input?: unknown;
  output?: string;
  success?: boolean;
  path?: string;
  diff?: string;
  status?: "thinking" | "idle";
  message?: string;
}

export interface OpenClawResponse {
  text: string;
  tools: string[];
  reasoning: string[];
}

// ─── Auth ────────────────────────────────────────────────

let _cachedToken: string | null = null;

function getGatewayToken(): string {
  if (_cachedToken) return _cachedToken;
  try {
    const configPath = join(homedir(), ".openclaw", "openclaw.json");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    _cachedToken = config?.gateway?.auth?.token || "";
  } catch {
    _cachedToken = "";
  }
  return _cachedToken ?? "";
}

// ─── Model Strategy ─────────────────────────────────────

// Human-readable labels for the chat UI
export const SESSION_MODEL_LABELS: Record<string, string> = {
  claude: "Claude Opus 4.6",
  codex: "GPT-4.1",
  gemini: "Gemini Pro",
  opencode: "MiniMax M2.5",
};

export function sessionToModel(
  _session: string,
  _threadModel?: string | null,
): string {
  // OpenClaw uses its configured default model; we don't override per-request
  return "openclaw";
}

export function sessionToCli(session: string): string {
  const SESSION_CLI: Record<string, string> = {
    claude: "claude",
    codex: "codex",
    gemini: "gemini",
    opencode: "opencode",
  };
  return SESSION_CLI[session] ?? "claude";
}

// ─── Active request tracking ────────────────────────────

const activeRequests: Map<string, AbortController> = new Map();

// ─── Circuit Breaker ────────────────────────────────────
// ONLY trips on gateway connectivity failures (connection refused, DNS, timeouts).
// Model quality issues (empty responses, 400s) do NOT trip the breaker —
// the gateway is fine, it's just the model that's bad.

const CIRCUIT_BREAKER_THRESHOLD = 5; // consecutive CONNECTIVITY failures to trip
const CIRCUIT_BREAKER_COOLDOWN_MS = 15_000; // 15s open state (short — user is waiting)
const MAX_RETRIES = 2; // quick retries — don't make user wait through 4 attempts
const RETRY_BACKOFF_MS = [1000, 2000]; // shorter backoff

interface CircuitBreakerState {
  status: "closed" | "open" | "half_open";
  consecutiveFailures: number;
  openedAt: number;
}

const circuitBreaker: CircuitBreakerState = {
  status: "closed",
  consecutiveFailures: 0,
  openedAt: 0,
};

function checkCircuitBreaker(): { allowed: boolean; reason?: string } {
  if (circuitBreaker.status === "closed") return { allowed: true };

  if (circuitBreaker.status === "open") {
    const elapsed = Date.now() - circuitBreaker.openedAt;
    if (elapsed >= CIRCUIT_BREAKER_COOLDOWN_MS) {
      circuitBreaker.status = "half_open";
      console.log("[OpenClaw] Circuit breaker half-open, allowing probe request");
      return { allowed: true };
    }
    const remaining = Math.ceil((CIRCUIT_BREAKER_COOLDOWN_MS - elapsed) / 1000);
    return {
      allowed: false,
      reason: `AI agent is reconnecting — try again in ${remaining}s`,
    };
  }

  return { allowed: true };
}

function recordConnectivitySuccess(): void {
  if (circuitBreaker.consecutiveFailures > 0 || circuitBreaker.status !== "closed") {
    console.log(`[OpenClaw] Circuit breaker reset (was ${circuitBreaker.status}, ${circuitBreaker.consecutiveFailures} failures)`);
  }
  circuitBreaker.consecutiveFailures = 0;
  circuitBreaker.status = "closed";
  circuitBreaker.openedAt = 0;
}

function recordConnectivityFailure(): void {
  circuitBreaker.consecutiveFailures++;
  if (circuitBreaker.consecutiveFailures >= CIRCUIT_BREAKER_THRESHOLD && circuitBreaker.status === "closed") {
    circuitBreaker.status = "open";
    circuitBreaker.openedAt = Date.now();
    console.log(`[OpenClaw] Circuit breaker OPEN after ${circuitBreaker.consecutiveFailures} consecutive connectivity failures`);
  } else if (circuitBreaker.status === "half_open") {
    circuitBreaker.status = "open";
    circuitBreaker.openedAt = Date.now();
    console.log("[OpenClaw] Circuit breaker probe failed, reopening");
  }
}

/** Check if an error is a true connectivity issue (vs model/response quality) */
function isConnectivityError(err: Error): boolean {
  // AbortError is intentional (user sent new message or request timed out) — NOT a connectivity issue.
  // Counting aborts as failures was causing the circuit breaker to trip on normal usage.
  if (err.name === "AbortError") return false;

  const msg = err.message.toLowerCase();
  return (
    msg.includes("econnrefused") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("enotfound") ||
    msg.includes("fetch failed") ||
    msg.includes("no response body") ||
    msg.includes("socket hang up") ||
    msg.includes("network")
  );
}

// ─── Message Sending ────────────────────────────────────

/**
 * Send a message to OpenClaw via the HTTP streaming API.
 * Streams response chunks via onChunk callback.
 * Returns accumulated response when complete.
 *
 * DESIGN: This function NEVER throws. It always returns an OpenClawResponse,
 * even on failure — with a user-friendly error message in response.text.
 * This guarantees the caller always has something to save/display,
 * and the next message always works (no hung state).
 *
 * Circuit breaker only trips on true connectivity failures (gateway down),
 * not on model quality issues (empty responses, bad tool calls).
 */
export async function sendToOpenClaw(
  threadId: string,
  message: string,
  session: string,
  onChunk: ChunkCallback,
  _threadModel?: string | null,
  project?: string | null,
  systemPrompt?: string | null,
): Promise<OpenClawResponse> {
  const errorResponse = (msg: string): OpenClawResponse => {
    onChunk({ type: "text", content: msg });
    onChunk({ type: "status", status: "idle" });
    return { text: msg, tools: [], reasoning: [] };
  };

  // Check circuit breaker — but still return a response, never throw
  const cbCheck = checkCircuitBreaker();
  if (!cbCheck.allowed) {
    console.log(`[OpenClaw] Circuit breaker open for thread ${threadId.substring(0, 8)}: ${cbCheck.reason}`);
    return errorResponse(`⚠️ ${cbCheck.reason}`);
  }

  // Abort any existing request for this thread (prevent stacking)
  const existing = activeRequests.get(threadId);
  if (existing) {
    existing.abort();
    activeRequests.delete(threadId);
  }

  const controller = new AbortController();
  activeRequests.set(threadId, controller);

  // Auto-abort after REQUEST_TIMEOUT_MS to prevent forever-hung requests
  // from clogging OpenClaw's internal lane queue.
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    if (!controller.signal.aborted) {
      timedOut = true;
      console.log(`[OpenClaw] Request timeout for thread ${threadId.substring(0, 8)} after ${REQUEST_TIMEOUT_MS / 1000}s`);
      controller.abort();
    }
  }, REQUEST_TIMEOUT_MS);

  const token = getGatewayToken();
  const model = project ? `openclaw:dev-${project}` : "openclaw";
  let lastError: Error | null = null;

  try {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        if (controller.signal.aborted) break;

        const healthy = await checkOpenClawHealth();
        if (!healthy) {
          console.log(`[OpenClaw] Gateway down on attempt ${attempt + 1} for thread ${threadId.substring(0, 8)}`);
          recordConnectivityFailure();
          return errorResponse("The AI agent is starting up. Please send your message again in a moment.");
        }

        const delay = RETRY_BACKOFF_MS[attempt - 1] ?? 2000;
        console.log(`[OpenClaw] Retry ${attempt}/${MAX_RETRIES} for thread ${threadId.substring(0, 8)} after ${delay}ms`);
        await new Promise((r) => setTimeout(r, delay));

        if (controller.signal.aborted) break;
      }

      try {
        console.log(
          `[OpenClaw] HTTP request for thread ${threadId.substring(0, 8)}, session=${session}, model=${model}${attempt > 0 ? ` (attempt ${attempt + 1})` : ""}`,
        );

        const httpResponse = await fetch(
          `${OPENCLAW_HTTP_URL}/v1/chat/completions`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: JSON.stringify({
              model,
              messages: [
                ...(systemPrompt ? [{ role: "system" as const, content: systemPrompt }] : []),
                { role: "user" as const, content: message },
              ],
              stream: true,
              user: threadId,
            }),
            signal: controller.signal,
          },
        );

        // Got an HTTP response — gateway is alive (reset connectivity breaker)
        recordConnectivitySuccess();

        if (!httpResponse.ok) {
          const errText = await httpResponse.text().catch(() => "unknown error");
          const status = httpResponse.status;
          console.warn(`[OpenClaw] HTTP ${status} for thread ${threadId.substring(0, 8)}: ${errText.slice(0, 200)}`);
          // Model/gateway returned an error — not a connectivity issue, don't retry
          // (the same request will get the same error)
          return errorResponse("Something went wrong processing your request. Please try again.");
        }

        const body = httpResponse.body;
        if (!body) {
          throw new Error("OpenClaw returned no response body");
        }

        // Parse SSE stream
        const response: OpenClawResponse = { text: "", tools: [], reasoning: [] };
        const reader = body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });

          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith(":")) continue;

            if (trimmed.startsWith("data: ")) {
              const data = trimmed.slice(6);
              if (data === "[DONE]") {
                onChunk({ type: "status", status: "idle" });
                continue;
              }

              try {
                const parsed = JSON.parse(data);
                const delta = parsed.choices?.[0]?.delta;
                const finishReason = parsed.choices?.[0]?.finish_reason;

                if (delta?.content) {
                  response.text += delta.content;
                  onChunk({ type: "text", content: delta.content });
                }

                // Detect tool calls — OpenClaw streams these as delta.tool_calls
                // in the OpenAI-compatible format. Emitting tool_use events lets
                // main.ts flush the narration buffer and show thinking steps,
                // so the user sees progress instead of "Thinking..." for minutes.
                if (delta?.tool_calls) {
                  for (const tc of delta.tool_calls as { index?: number; id?: string; function?: { name?: string; arguments?: string } }[]) {
                    if (tc.function?.name) {
                      const toolName = tc.function.name;
                      if (!response.tools.includes(toolName)) {
                        response.tools.push(toolName);
                      }
                      onChunk({ type: "tool_use", tool: toolName });
                    }
                  }
                }

                if (delta?.reasoning_content) {
                  response.reasoning.push(delta.reasoning_content);
                }

                if (finishReason === "stop") {
                  onChunk({ type: "status", status: "idle" });
                }

                // OpenClaw terminates requests when the lane is overloaded
                // (stale requests from rapid user messages). Treat as completion
                // with whatever text was accumulated so far.
                if (finishReason === "terminated") {
                  console.warn(`[OpenClaw] Request terminated by gateway for thread ${threadId.substring(0, 8)} (lane overloaded)`);
                  onChunk({ type: "status", status: "idle" });
                }
              } catch {
                // Malformed SSE data — skip
              }
            }
          }
        }

        console.log(
          `[OpenClaw] Response complete for thread ${threadId.substring(0, 8)}, ${response.text.length} chars`,
        );

        // Empty response — model probably tried tool calls that failed silently.
        // Return a visible message instead of blank. Don't retry (same model = same result).
        if (!response.text.trim()) {
          console.warn(`[OpenClaw] Empty response for thread ${threadId.substring(0, 8)} — model returned no text`);
          return errorResponse("I wasn't able to complete that request. Please try sending your message again.");
        }

        return response;
      } catch (err) {
        lastError = err as Error;
        if (lastError.name === "AbortError") break;

        console.error(
          `[OpenClaw] Attempt ${attempt + 1} failed for thread ${threadId.substring(0, 8)}: ${lastError.message}`,
        );

        // Only retry on connectivity errors — model errors won't improve on retry
        if (!isConnectivityError(lastError)) {
          return errorResponse("Something went wrong processing your request. Please try again.");
        }

        if (attempt >= MAX_RETRIES) break;
      }
    }

    // All retries exhausted — this is a connectivity issue
    if (lastError && isConnectivityError(lastError)) {
      recordConnectivityFailure();
    }

    if (lastError?.name === "AbortError") {
      if (timedOut) {
        return errorResponse("The request timed out. Please try again with a simpler message.");
      }
      return { text: "", tools: [], reasoning: [] }; // intentional cancel — no message needed
    }

    return errorResponse("The AI agent is not responding right now. Please try again in a moment.");
  } finally {
    clearTimeout(timeoutId);
    activeRequests.delete(threadId);
  }
}

// ─── Lifecycle ──────────────────────────────────────────

/**
 * Cancel and clean up a thread's active request.
 */
export function closeOpenClawConnection(threadId: string): void {
  const controller = activeRequests.get(threadId);
  if (controller) {
    controller.abort();
    activeRequests.delete(threadId);
    console.log(
      `[OpenClaw] Cancelled request for thread ${threadId.substring(0, 8)}`,
    );
  }
}

/**
 * Cancel all active OpenClaw requests.
 */
export function closeAllOpenClawConnections(): void {
  for (const [threadId, controller] of activeRequests) {
    controller.abort();
    console.log(
      `[OpenClaw] Cancelled request for thread ${threadId.substring(0, 8)}`,
    );
  }
  activeRequests.clear();
}

/**
 * Check if OpenClaw gateway is reachable via HTTP.
 */
export async function checkOpenClawHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${OPENCLAW_HTTP_URL}/__openclaw__/canvas/`, {
      method: "GET",
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
