// State shared by every window of the editor, kept as files in the extension's global
// storage folder. globalState is per window in memory, so two windows writing it
// overwrite each other's additions; files give one source of truth, atomic writes,
// and an exclusive create that only one window can win.

import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

export class FileStore {
  constructor(readonly dir: string) {}

  private file(name: string): string {
    return path.join(this.dir, name);
  }

  async readJson<T>(name: string, fallback: T): Promise<T> {
    try {
      return JSON.parse(await fs.readFile(this.file(name), "utf8")) as T;
    } catch {
      return fallback;
    }
  }

  /** Atomic: readers see the old file or the new one, never half of one. */
  async writeJson(name: string, value: unknown): Promise<void> {
    await fs.mkdir(path.dirname(this.file(name)), { recursive: true });
    const tmp = this.file(`${name}.${randomUUID()}.tmp`);
    await fs.writeFile(tmp, JSON.stringify(value));
    await fs.rename(tmp, this.file(name));
  }

  private claimFile(key: string): string {
    const name = createHash("sha256").update(key).digest("hex").slice(0, 32);
    return path.join(this.file("notified"), name);
  }

  /**
   * True for exactly one caller across all windows, the first to claim `key` (an
   * exclusive file create). Used so one warning is shown once, in one window.
   */
  async claimOnce(key: string): Promise<boolean> {
    await fs.mkdir(this.file("notified"), { recursive: true });
    try {
      await fs.writeFile(this.claimFile(key), key, { flag: "wx" });
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw err;
    }
  }

  /** Lets a claimed warning be shown again ("Warn Me Again"). */
  async unclaim(key: string): Promise<void> {
    await fs.rm(this.claimFile(key), { force: true });
  }

  /** Every JSON file in a subfolder, parsed; unreadable ones are skipped. */
  async readAll<T>(sub: string): Promise<{ name: string; value: T }[]> {
    let names: string[];
    try {
      names = (await fs.readdir(this.file(sub))).filter((n) => n.endsWith(".json"));
    } catch {
      return [];
    }
    const values = await Promise.all(
      names.map((n) => this.readJson<T | undefined>(path.join(sub, n), undefined)),
    );
    return names.flatMap((name, i) => (values[i] === undefined ? [] : [{ name, value: values[i]! }]));
  }

  async remove(name: string): Promise<void> {
    await fs.rm(this.file(name), { force: true });
  }
}

/**
 * One window at a time runs the checks: a lock file holding the owner's ID and a
 * heartbeat. A lock not refreshed for STALE_MS (window closed or crashed) can be taken.
 */
export class Leader {
  static readonly STALE_MS = 90_000;
  readonly id = randomUUID();

  constructor(
    private readonly dir: string,
    private readonly now: () => number = Date.now,
    private readonly settle: () => Promise<void> = () => new Promise((r) => setTimeout(r, 150)),
  ) {}

  private get file(): string {
    return path.join(this.dir, "scan.lock");
  }

  private async read(): Promise<{ id: string; at: number } | undefined> {
    try {
      const v = JSON.parse(await fs.readFile(this.file, "utf8"));
      return typeof v?.id === "string" && typeof v?.at === "number" ? v : undefined;
    } catch {
      return undefined;
    }
  }

  private queue: Promise<unknown> = Promise.resolve();
  private released = false;

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Take or refresh the lock. False when another live window holds it. Calls in one
   * window run one at a time, and every write is read back after a pause: of windows
   * writing at once (two taking a stale lock, or one waking from sleep with an old
   * view of it), the last writer keeps it. A writer slower than the pause can lead
   * alongside it until its next heartbeat reads the other's ID and backs off — at
   * worst some duplicate requests for one heartbeat.
   */
  acquire(): Promise<boolean> {
    return this.enqueue(() => this.acquireNow());
  }

  private async acquireNow(): Promise<boolean> {
    if (this.released) return false; // the window is closing
    const cur = await this.read();
    if (cur && cur.id !== this.id && this.now() - cur.at < Leader.STALE_MS) return false;
    await fs.mkdir(this.dir, { recursive: true });
    const tmp = `${this.file}.${randomUUID()}.tmp`;
    await fs.writeFile(tmp, JSON.stringify({ id: this.id, at: this.now() }));
    await fs.rename(tmp, this.file);
    await this.settle();
    return (await this.read())?.id === this.id;
  }

  /** Gives up the lock for good (window closing); after an acquire still in flight. */
  release(): Promise<void> {
    this.released = true;
    return this.enqueue(async () => {
      if ((await this.read())?.id === this.id) await fs.rm(this.file, { force: true });
    });
  }
}
