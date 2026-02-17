/**
 * Zen Model Discovery Service
 *
 * Auto-discovers free models from OpenCode's Zen endpoint and selects
 * the best one. Refreshes every 30 minutes.
 *
 * Free models: identified by `-free` suffix or known names (big-pickle, etc.)
 * Ranking: kimi > glm > minimax > others (based on quality)
 */

import { setModel, getCurrentModel } from './cli-streaming.service';
import { ZEN_MODELS_URL, ZEN_REFRESH_MS } from '../config';

// Free model identification
const FREE_MODELS = new Set(['big-pickle', 'trinity-large-preview-free']);
function isFreeModel(id: string): boolean {
  return id.endsWith('-free') || FREE_MODELS.has(id);
}

// Ranking: tool-calling models first, then by specificity
const RANK_PREFIXES = ['kimi-', 'glm-', 'minimax-'];
function rankModel(id: string): number {
  const idx = RANK_PREFIXES.findIndex(p => id.startsWith(p));
  return idx === -1 ? 999 : idx;
}

export interface ZenModel {
  id: string;
  openCodeId: string;
}

let cachedModels: ZenModel[] = [];
let currentBest: string | null = null;

export async function discoverZenModels(): Promise<ZenModel[]> {
  const res = await fetch(ZEN_MODELS_URL, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) return cachedModels; // keep stale on failure
  const data = (await res.json()) as { data?: { id: string }[] };
  const all = data.data || [];
  const free = all
    .filter(m => isFreeModel(m.id))
    .map(m => ({ id: m.id, openCodeId: `opencode/${m.id}` }))
    .sort((a, b) => rankModel(a.id) - rankModel(b.id));
  return free;
}

export async function refreshZenModels(): Promise<void> {
  const models = await discoverZenModels();
  if (models.length === 0) return;
  cachedModels = models;
  const best = models[0]!.openCodeId;
  if (best !== currentBest) {
    const current = await getCurrentModel();
    // Only auto-switch if user hasn't manually picked a model
    // (current is null, proxy model, or a previous auto-pick)
    if (!current || current.startsWith('ellulai/') || current === currentBest) {
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
