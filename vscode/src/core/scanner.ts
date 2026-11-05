// Decides what to send, sends it in batches, polls "pending" until the server finishes,
// and records each result. No VS Code imports: driven by tests with fakes.

import { MAX_PER_REQUEST, type ExtensionResult, type ScanResponse } from "./api";
import { refKey, type ExtensionRef } from "./inventory";

export interface StoredResult extends ExtensionResult {
  checkedAt: number;
  /** Ask again from this time, earlier than the usual schedule (set when a re-check
   * came back "unknown" and the previous verdict was kept). */
  retryAt?: number;
}

const HOUR = 3_600_000;
/** A finished verdict is re-asked weekly: the server re-scans with newer rules and CVE
 * data, and the same version is only billed once per 30 days. */
export const RECHECK_FINISHED_MS = 7 * 24 * HOUR;
/** "unknown" (store down, quota cut, not in the store) is retried daily. */
export const RECHECK_UNKNOWN_MS = 24 * HOUR;
/** Stop polling a scan that hasn't finished after this long; the next run picks it up. */
export const PENDING_DEADLINE_MS = 30 * 60_000;
/** Results for extensions no longer installed (or disabled in this window) are kept
 * this long, so re-enabling one doesn't need a new check. */
export const FORGET_AFTER_MS = 30 * 24 * HOUR;
const FINISHED = new Set(["malicious", "high", "medium", "clean"]);
const MIN_POLL_MS = 10_000;
const MAX_POLL_MS = 120_000;

export function isDue(stored: StoredResult | undefined, now: number): boolean {
  if (!stored) return true;
  const age = now - stored.checkedAt;
  if (age < 0) return true; // clock went backwards
  if (stored.verdict === "pending") return true;
  if (stored.retryAt !== undefined && now >= stored.retryAt) return true;
  if (stored.verdict === "unknown") return age >= RECHECK_UNKNOWN_MS;
  return age >= RECHECK_FINISHED_MS;
}

export interface ScannerDeps {
  scan(refs: ExtensionRef[]): Promise<ScanResponse>;
  load(): Promise<Record<string, StoredResult>>;
  save(results: Record<string, StoredResult>): Promise<void>;
  /** Called after every response with the results it brought. */
  onResults(results: StoredResult[]): void;
  /** Whether the plan's quota was used up, from the latest response. */
  onQuota(exhausted: boolean): void;
  now(): number;
  /** Waits between polls; may return early (e.g. when an extension is installed). */
  sleep(ms: number): Promise<void>;
  log(message: string): void;
}

export interface RunOptions {
  /** Ask about every installed extension, not only those due. */
  force?: boolean;
  /** Checked between polls; a cancelled run returns quietly. */
  isCancelled?: () => boolean;
}

export class Scanner {
  constructor(private readonly deps: ScannerDeps) {}

  /**
   * Check what `installed()` returns. It is read again before every poll, so an
   * extension installed during a long first audit is sent on the next poll instead of
   * waiting for the audit to finish. Throws AuthError / ApiError from the client;
   * results received before the error are kept.
   */
  async run(installed: () => ExtensionRef[], opts: RunOptions = {}): Promise<void> {
    const d = this.deps;
    let stored = this.prune(await d.load(), installed());
    await d.save(stored);
    const deadline = d.now() + PENDING_DEADLINE_MS;
    // Re-checks that came back "pending" keep their old verdict in `stored`, so they
    // aren't "due"; this set keeps polling them.
    const polling = new Set<string>();
    // Each extension is sent once per run, plus its pending polls: an answer the server
    // leaves out (or one still "due" after answering) can't loop the run.
    const sent = new Set<string>();
    let wait = MIN_POLL_MS;
    for (;;) {
      const now = d.now();
      const todo = installed().filter((r) => {
        const k = refKey(r);
        return polling.has(k) || (!sent.has(k) && (opts.force || isDue(stored[k], now)));
      });
      if (!todo.length) return;
      d.log(`Checking ${todo.length} extension(s)`);
      for (const r of todo) sent.add(refKey(r));
      polling.clear();

      let retryAfter = 0;
      for (let i = 0; i < todo.length; i += MAX_PER_REQUEST) {
        const batch = todo.slice(i, i + MAX_PER_REQUEST);
        const res = await d.scan(batch);
        d.onQuota(res.quota_exhausted === true);
        // Re-read: another window may have recorded results meanwhile.
        stored = { ...(await d.load()), ...stored };
        const asked = new Set(batch.map(refKey));
        const changed: StoredResult[] = [];
        for (const r of res.results) {
          const k = refKey(r);
          if (!asked.has(k)) continue; // not something we asked about
          if (r.verdict === "pending") {
            retryAfter = Math.max(retryAfter, (r.retry_after_seconds ?? 0) * 1000);
            polling.add(k);
            // Keep the last real verdict while a re-check runs.
            if (stored[k] && stored[k].verdict !== "pending") continue;
          }
          const prev = stored[k];
          if (r.verdict === "unknown" && prev && FINISHED.has(prev.verdict)) {
            // "unknown" (quota used up, store or scanner down) never erases a real
            // verdict: keep it, and ask again on the unknown schedule.
            stored[k] = { ...prev, retryAt: d.now() + RECHECK_UNKNOWN_MS };
            continue;
          }
          const rec: StoredResult = { ...r, checkedAt: d.now() };
          stored[k] = rec;
          changed.push(rec);
        }
        await d.save(stored);
        if (changed.length) d.onResults(changed);
      }

      if (!polling.size) {
        // Nothing pending; something installed while we were sending is picked up
        // by the next loop, and the loop ends when nothing is due.
        continue;
      }
      if (opts.isCancelled?.()) return;
      if (d.now() >= deadline) {
        d.log(`${polling.size} scan(s) still running on the server; will ask again later`);
        return;
      }
      await d.sleep(Math.min(MAX_POLL_MS, Math.max(wait, retryAfter)));
      wait = Math.min(MAX_POLL_MS, Math.round(wait * 1.5));
      if (opts.isCancelled?.()) return;
    }
  }

  /** Forget results for extensions not installed here for FORGET_AFTER_MS. */
  private prune(
    stored: Record<string, StoredResult>,
    installed: ExtensionRef[],
  ): Record<string, StoredResult> {
    const keep = new Set(installed.map(refKey));
    const now = this.deps.now();
    const out: Record<string, StoredResult> = {};
    for (const [k, v] of Object.entries(stored)) {
      if (keep.has(k) || now - v.checkedAt < FORGET_AFTER_MS) out[k] = v;
    }
    return out;
  }
}

export const SEVERITY_ORDER: Record<string, number> = {
  malicious: 0,
  high: 1,
  medium: 2,
  pending: 3,
  unknown: 4,
  clean: 5,
};

/**
 * Ignoring is per extension version AND verdict: ignoring a medium (CVE) warning must
 * not hide a later malicious verdict for the same version. Entries are "key|verdict";
 * a verdict is ignored when an entry for that key is at least as severe.
 */
export function isIgnored(ignored: Iterable<string>, key: string, verdict: string): boolean {
  const rank = SEVERITY_ORDER[verdict] ?? 9;
  for (const e of ignored) {
    const cut = e.lastIndexOf("|");
    if (cut < 0 || e.slice(0, cut) !== key) continue;
    if ((SEVERITY_ORDER[e.slice(cut + 1)] ?? 9) <= rank) return true;
  }
  return false;
}

/** What to tell the user about one finished result. */
export function notification(
  r: Pick<ExtensionResult, "verdict">,
  opts: { notifyMedium: boolean; ignored: boolean },
): "modal" | "toast" | null {
  if (opts.ignored) return null;
  if (r.verdict === "malicious" || r.verdict === "high") return "modal";
  if (r.verdict === "medium" && opts.notifyMedium) return "toast";
  return null;
}
