/**
 * Agent Bridge Authentication
 *
 * UNIFIED AUTH: All tiers require agent token validated via sovereign-shield.
 * Sovereign-shield is the single source of truth for all tier/auth logic.
 */

/**
 * Validate agent token via sovereign-shield.
 */
export async function validateAgentToken(token: string): Promise<boolean> {
  try {
    const res = await fetch('http://127.0.0.1:3005/_auth/agent/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const data = (await res.json()) as { valid?: boolean };
    return data.valid === true;
  } catch (e) {
    const error = e as Error;
    console.error('[Bridge] Agent token validation error:', error.message);
    return false;
  }
}

/**
 * Extract agent token from URL query string.
 */
export function extractAgentToken(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url, 'http://localhost');
    return parsed.searchParams.get('_agent_token');
  } catch {
    return null;
  }
}
