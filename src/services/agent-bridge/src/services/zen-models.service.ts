/**
 * Zen Model Discovery Service
 *
 * Auto-discovers free models from OpenCode's Zen endpoint and selects
 * the best one. Refreshes every 30 minutes.
 *
 * All models from Zen are treated as free — no hardcoded model names.
 * Quality ranking is heuristic: extract version numbers from model IDs
 * (higher = better), prefer "large" variants, deprioritize unversioned models.
 */

import { execSync } from 'child_process';
import { setModel, getCurrentModel } from './cli-streaming.service';
import { ZEN_MODELS_URL, ZEN_REFRESH_MS, OPENCODE_BIN } from '../config';

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
 * Get locally available models from `opencode models` command.
 * Returns the set of model IDs (with opencode/ prefix) that the local binary supports.
 */
function getLocalModels(): Set<string> {
  try {
    const output = execSync(`${OPENCODE_BIN} models 2>/dev/null`, { timeout: 5000 }).toString().trim();
    // Each line is like "opencode/big-pickle"
    return new Set(output.split('\n').map(l => l.trim()).filter(Boolean));
  } catch {
    return new Set();
  }
}

export interface ZenModel {
  id: string;
  openCodeId: string;
}

let cachedModels: ZenModel[] = [];
let currentBest: string | null = null;

export async function discoverZenModels(): Promise<ZenModel[]> {
  // Get locally available models to cross-reference
  const localModels = getLocalModels();

  const res = await fetch(ZEN_MODELS_URL, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return cachedModels; // keep stale on failure
  const data = (await res.json()) as { data?: { id: string }[] };
  const all = data.data || [];
  // All Zen models are free — no hardcoded name filtering needed.
  // Sort by quality heuristic (highest version number first).
  const available = all
    .map(m => ({ id: m.id, openCodeId: `opencode/${m.id}` }))
    .filter(m => localModels.size === 0 || localModels.has(m.openCodeId))
    .sort((a, b) => modelQualityScore(b.id) - modelQualityScore(a.id));
  return available;
}

export async function refreshZenModels(): Promise<void> {
  const models = await discoverZenModels();
  if (models.length === 0) return;
  cachedModels = models;
  const best = models[0]!.openCodeId;
  if (best !== currentBest) {
    const current = await getCurrentModel();
    // Only auto-switch if user hasn't manually picked a non-opencode model
    // (current is null, not an opencode model, or a previous auto-pick)
    if (!current || !current.startsWith('opencode/') || current === currentBest) {
      await setModel(best);
      console.log(`[Zen] Switched model: ${currentBest} → ${best}`);
    }
    currentBest = best;
  }
}

export function startZenModelRefresh(): void {
  refreshZenModels().catch(err =>
    console.warn('[Zen] Initial discovery failed:', (err as Error).message)
  );
  setInterval(
    () =>
      refreshZenModels().catch(err =>
        console.warn('[Zen] Refresh failed:', (err as Error).message)
      ),
    ZEN_REFRESH_MS
  );
}

export function getZenModelList(): ZenModel[] {
  return cachedModels;
}

export function getBestZenModel(): string | null {
  return currentBest;
}
