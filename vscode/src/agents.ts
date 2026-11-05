// "Coding Agents": connect Claude Code and Codex to AgentGuards by running the official
// installer (the `agentguards` CLI), and show whether each one is protected.

import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { installerKey } from "./auth";
import { isAgentGuardsKey } from "./core/api";
import {
  assetName,
  connectable,
  effectiveState,
  savedKeyRejected,
  withKeyStatus,
  KNOWN_AGENT_IDS,
  type Effective,
  type SavedKey,
  parseDoctor,
  RELEASE_BASE,
  sha256,
  verifyDownload,
  type DoctorAgent,
  type DoctorReport,
} from "./core/installer";

const MAX_BINARY_BYTES = 64 * 1024 * 1024;
/** The managed copy is refreshed from the latest release this often. */
const REFRESH_BINARY_MS = 7 * 24 * 60 * 60_000;
const DOWNLOAD_TIMEOUT_MS = 120_000;
const DOCTOR_TIMEOUT_MS = 60_000;
/** A superseded installer version or abandoned download is removed after this long. */
const CLEANUP_GRACE_MS = 60 * 60_000;

export type Status =
  | { kind: "unknown" }
  | { kind: "checking" }
  | { kind: "ok"; report: DoctorReport }
  | { kind: "unavailable"; message: string };

async function fetchBytes(url: string): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOWNLOAD_TIMEOUT_MS);
  try {
    // No credentials are involved: GitHub's release download redirects to its CDN.
    const res = await fetch(url, { signal: controller.signal, redirect: "follow" });
    if (!res.ok) throw new Error(`download failed (HTTP ${res.status}): ${url}`);
    const len = Number(res.headers.get("content-length") ?? 0);
    if (len > MAX_BINARY_BYTES) throw new Error("download is unexpectedly large");
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > MAX_BINARY_BYTES) throw new Error("download is unexpectedly large");
    return buf;
  } finally {
    clearTimeout(timer);
  }
}

interface Current {
  file: string;
  sha256: string;
  checkedAt: number;
}

/**
 * The installer binary, kept in the extension's storage. Each verified download is
 * stored under a name that includes its hash (so a Windows .exe that is running is
 * never overwritten), and its hash is checked again before every run.
 */
export class Installer {
  private pending: Promise<string> | undefined;
  private pendingUpdate: Promise<string> | undefined;
  /** When an update attempt last failed: not retried for an hour (offline, proxy). */
  private failedAt = 0;
  /** The binary that last answered with usage text instead of JSON (too old). */
  private outdated: string | undefined;
  private lastUpdateError: string | undefined;

  constructor(
    private readonly dir: string,
    private readonly log: (m: string) => void,
  ) {}

  private get binDir(): string {
    return path.join(this.dir, "bin");
  }

  private async current(): Promise<Current | undefined> {
    try {
      const c = JSON.parse(await fs.readFile(path.join(this.binDir, "current.json"), "utf8"));
      return typeof c?.file === "string" && typeof c?.sha256 === "string" ? c : undefined;
    } catch {
      return undefined;
    }
  }

  /** stat fingerprint → hash, so an unchanged file isn't re-read on every refresh. */
  private hashed = new Map<string, string>();

  /**
   * The binary, if it is still exactly what was verified. This catches a file that
   * was corrupted, truncated, or swapped by a sync/backup tool. It is not a defence
   * against another program running as the user, which could replace the file
   * between this check and the run — but such a program could equally edit the
   * user's agent config or shell profile directly.
   */
  private async verified(c: Current | undefined): Promise<string | undefined> {
    if (!c) return undefined;
    const file = path.join(this.binDir, path.basename(c.file));
    try {
      const st = await fs.stat(file);
      const fp = `${file}:${st.size}:${st.mtimeMs}:${st.ino}`;
      let h = this.hashed.get(fp);
      if (!h) {
        h = sha256(await fs.readFile(file));
        this.hashed.set(fp, h);
      }
      if (h === c.sha256) return file;
      this.log("the installer on disk changed since it was verified; downloading it again");
    } catch {
      /* missing */
    }
    return undefined;
  }

  /** Path to a verified installer; downloads it when missing, stale, changed or `update`. */
  binary(update = false): Promise<string> {
    // Testing an unreleased installer: an environment variable, never a setting (a
    // workspace must not be able to choose which program this runs).
    const dev = process.env.AGENTGUARDS_INSTALLER;
    if (dev) return Promise.resolve(dev);
    if (update) {
      // Never satisfied by a plain lookup already in flight: run the update after it.
      this.pendingUpdate ??= (this.pending ?? Promise.resolve())
        .catch(() => undefined)
        .then(() => this.ensure(true))
        .finally(() => (this.pendingUpdate = undefined));
      return this.pendingUpdate;
    }
    this.pending ??= this.ensure(false).finally(() => (this.pending = undefined));
    return this.pending;
  }

  private async ensure(update: boolean): Promise<string> {
    const asset = assetName(process.platform, process.arch);
    if (!asset) throw new Error(`the AgentGuards installer has no build for ${process.platform}/${process.arch}`);
    const cur = await this.current();
    const file = await this.verified(cur);
    if (cur && Date.now() - cur.checkedAt > CLEANUP_GRACE_MS) void this.cleanup(cur.file);
    const stale = !cur || Date.now() - cur.checkedAt >= REFRESH_BINARY_MS;
    if (file && !update && !stale) return file;
    if (file && Date.now() - this.failedAt < 60 * 60_000) return file;
    try {
      this.log(`downloading the AgentGuards installer (${asset})`);
      const [bin, sums] = await Promise.all([
        fetchBytes(`${RELEASE_BASE}/${asset}`),
        fetchBytes(`${RELEASE_BASE}/SHA256SUMS`).then((b) => new TextDecoder().decode(b)),
      ]);
      verifyDownload(bin, sums, asset);
      const hash = sha256(bin);
      const ext = asset.endsWith(".exe") ? ".exe" : "";
      const name = `agentguards-${hash.slice(0, 16)}${ext}`;
      const target = path.join(this.binDir, name);
      await fs.mkdir(this.binDir, { recursive: true });
      const same = { file: name, sha256: hash, checkedAt: 0 };
      if (!(await this.verified(same))) {
        const tmp = `${target}.${process.pid}.${randomUUID()}.tmp`;
        try {
          await fs.writeFile(tmp, bin, { mode: 0o755 });
          await fs.rename(tmp, target);
        } catch (err) {
          // Another window put the same verified file there first (on Windows the
          // rename fails while that window runs it): use theirs.
          if (!(await this.verified(same))) throw err;
        } finally {
          await fs.rm(tmp, { force: true });
        }
      }
      const next: Current = { file: name, sha256: hash, checkedAt: Date.now() };
      const tmpCur = path.join(this.binDir, `current.json.${randomUUID()}.tmp`);
      await fs.writeFile(tmpCur, JSON.stringify(next));
      await fs.rename(tmpCur, path.join(this.binDir, "current.json"));
      this.lastUpdateError = undefined;
      return target;
    } catch (err) {
      this.failedAt = Date.now();
      this.lastUpdateError = (err as Error).message;
      // Offline or GitHub down: the verified copy we have still works.
      if (file) {
        this.log(`installer update failed, using the verified copy: ${(err as Error).message}`);
        return file;
      }
      throw err;
    }
  }

  /**
   * Removes superseded versions and abandoned downloads. Only runs once the current
   * version has been current for CLEANUP_GRACE_MS, and only removes temp files older
   * than that, so another window is never left holding a path that was just deleted
   * or a download that was cut off. A file still running (Windows) is retried later.
   */
  private async cleanup(keep: string): Promise<void> {
    const names = await fs.readdir(this.binDir).catch(() => [] as string[]);
    for (const n of names) {
      if (n === keep || n === "current.json") continue;
      if (!n.startsWith("agentguards") && !(n.startsWith("current.json.") && n.endsWith(".tmp"))) continue;
      const p = path.join(this.binDir, n);
      // Anything written recently may be another window's new download or the version
      // it just made current (its current.json may be newer than ours): leave it.
      const st = await fs.stat(p).catch(() => undefined);
      if (!st || Date.now() - st.mtimeMs < CLEANUP_GRACE_MS) continue;
      await fs.rm(p, { force: true }).catch(() => undefined);
    }
  }

  /**
   * `doctor --json --offline --check-agent-keys`: each agent's state, and whether the
   * key it sends works — checked with a read-only request that uses no quota.
   */
  async status(checkKeys: boolean): Promise<Status> {
    let bin: string;
    try {
      bin = await this.binary();
    } catch (err) {
      return { kind: "unavailable", message: (err as Error).message };
    }
    let res = await this.doctor(bin, checkKeys);
    if (res.missing) {
      // Removed by another window's cleanup between the check and the run.
      bin = await this.binary().catch(() => bin);
      res = await this.doctor(bin, checkKeys);
      if (res.missing) {
        return {
          kind: "unavailable",
          message:
            "The AgentGuards installer file is missing — security software may have removed it. It is downloaded again on the next check.",
        };
      }
    }
    if (res.outdated && this.outdated !== bin) {
      // Older than `doctor --json`: fetch the latest release, once per binary.
      let fresh = bin;
      try {
        fresh = await this.binary(true);
      } catch {
        /* reported below */
      }
      if (fresh === bin) {
        if (this.lastUpdateError) {
          // Not updated (offline, or retried too soon): say so; don't remember it as
          // "the release is too old", or a later release would never be fetched.
          return {
            kind: "unavailable",
            message: `Couldn't download the latest AgentGuards installer: ${this.lastUpdateError}. It will be retried.`,
          };
        }
        // Downloaded fine, and the latest release is this same file: it's too old.
        this.outdated = bin;
        return {
          kind: "unavailable",
          message: "This needs a newer AgentGuards installer than the one released. Try again later.",
        };
      }
      this.outdated = bin;
      bin = fresh;
      res = await this.doctor(bin, checkKeys);
    }
    if (res.report) return { kind: "ok", report: res.report };
    if (res.outdated) {
      this.outdated = bin;
      return {
        kind: "unavailable",
        message: "This needs a newer AgentGuards installer than the one released. Try again later.",
      };
    }
    return { kind: "unavailable", message: `The installer's status check failed: ${res.error}` };
  }

  private doctor(
    bin: string,
    checkKeys: boolean,
  ): Promise<{ report?: DoctorReport; outdated?: boolean; missing?: boolean; error?: string }> {
    // Report only what the agents themselves will have: a key in VS Code's own
    // environment is invisible to an agent started from the dock or another shell.
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.AGENTGUARDS_API_KEY;
    return new Promise((resolve) => {
      // Exit status 1 means "problems found" — the report is still on stdout.
      execFile(
        bin,
        ["doctor", "--json", "--offline", ...(checkKeys ? ["--check-agent-keys"] : [])],
        { timeout: DOCTOR_TIMEOUT_MS, windowsHide: true, maxBuffer: 1024 * 1024, env },
        (err, stdout, stderr) => {
          if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") return resolve({ missing: true });
          const report = parseDoctor(String(stdout ?? ""));
          if (report) return resolve({ report });
          const text = `${stdout ?? ""}${stderr ?? ""}`;
          if (/flag provided but not defined/.test(text)) return resolve({ outdated: true });
          resolve({ error: firstLine(String(stderr || err?.message || "no output")) });
        },
      );
    });
  }

  /**
   * Runs `agentguards install --yes --agents <ids>` in a visible terminal, so the user
   * sees exactly what it does. Resolves with the exit code.
   */
  async install(ids: string[], key: string | undefined, savedKeyRejected: boolean): Promise<number> {
    const agents = ids.filter((id) => KNOWN_AGENT_IDS.has(id));
    if (!agents.length) return 0;
    const bin = await this.binary();
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.AGENTGUARDS_API_KEY;
    // A saved key that works is kept: the installer saves an env key BEFORE testing it,
    // so handing it this editor's key could replace a working key with a broken one.
    // With no saved key, or one AgentGuards rejected, it gets this editor's key (else
    // it would start another browser sign-in) — through the environment, never the
    // command line (visible in the process list and the terminal).
    const saved = await installerKey();
    if ((!saved || savedKeyRejected) && key && isAgentGuardsKey(key)) env.AGENTGUARDS_API_KEY = key;
    const args = ["install", "--yes", "--agents", agents.join(",")];

    return new Promise<number>((resolve) => {
      const write = new vscode.EventEmitter<string>();
      const close = new vscode.EventEmitter<number | void>();
      const out = (s: string) => write.fire(s.replace(/\r?\n/g, "\r\n"));
      let child: ReturnType<typeof spawn> | undefined;
      let done = false;
      const finish = (code: number) => {
        if (!done) {
          done = true;
          resolve(code);
        }
      };
      const pty: vscode.Pseudoterminal = {
        onDidWrite: write.event,
        onDidClose: close.event,
        open: () => {
          out(`$ agentguards ${args.join(" ")}\n\n`);
          child = spawn(bin, args, { env, windowsHide: true, cwd: os.homedir() });
          // Decode as UTF-8 across chunk boundaries (✓ / ✗ are multi-byte).
          child.stdout?.setEncoding("utf8");
          child.stderr?.setEncoding("utf8");
          child.stdout?.on("data", (d: string) => out(d));
          child.stderr?.on("data", (d: string) => out(d));
          child.on("error", (e) => {
            out(`\n✗ could not run the installer: ${e.message}\n`);
            finish(1);
          });
          child.on("close", (code) => {
            out(`\n[AgentGuards installer finished${code ? ` with exit code ${code}` : ""}]\n`);
            finish(code ?? 1);
          });
        },
        close: () => child?.kill(),
      };
      const term = vscode.window.createTerminal({ name: "AgentGuards", pty });
      term.show();
    });
  }
}

function firstLine(s: string): string {
  return s.split(/\r?\n/).find((l) => l.trim()) ?? s;
}

// ---- view -----------------------------------------------------------------------------

type Node =
  | { kind: "agent"; agent: DoctorAgent }
  | { kind: "note"; label: string; icon: string; tip?: string; command?: vscode.Command };

export class AgentsTree implements vscode.TreeDataProvider<Node> {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  status: Status = { kind: "unknown" };
  saved: SavedKey = "unknown";

  set(status: Status, saved?: SavedKey): void {
    this.status = status;
    if (saved) this.saved = saved;
    this.emitter.fire(undefined);
  }

  getChildren(node?: Node): Node[] {
    if (node) return [];
    const s = this.status;
    if (s.kind === "unknown") return [];
    if (s.kind === "checking") return [{ kind: "note", label: "Checking…", icon: "sync~spin" }];
    if (s.kind === "unavailable") {
      return [
        { kind: "note", label: "Couldn't check your coding agents", icon: "warning", tip: s.message },
        { kind: "note", label: s.message, icon: "info", tip: s.message },
      ];
    }
    const nodes: Node[] = s.report.agents.map((agent) => ({ kind: "agent", agent }));
    const present = s.report.agents.some((a) => a.state !== "not_found");
    if (present && !s.report.hook_runtime_ok) {
      const msg = s.report.checks.find((c) => !c.ok && /python/i.test(c.message))?.message;
      nodes.push({
        kind: "note",
        label: "Install Python 3: the hooks can't run without it",
        icon: "warning",
        tip: msg,
      });
    }
    if (s.report.agents.every((a) => a.state === "not_found")) {
      nodes.push({
        kind: "note",
        label: "Install the Claude Code or Codex CLI, then refresh",
        icon: "info",
        tip: "AgentGuards connects the claude and codex command-line tools.",
      });
    }
    return nodes;
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === "note") {
      const item = new vscode.TreeItem(node.label);
      item.iconPath = new vscode.ThemeIcon(node.icon);
      item.tooltip = node.tip;
      item.command = node.command;
      return item;
    }
    const a = node.agent;
    const s = this.status;
    const eff: Effective =
      s.kind === "ok" ? effectiveState(s.report, a, this.saved) : { level: "unverified", label: "", connectable: false };
    const item = new vscode.TreeItem(a.name);
    item.id = `agent:${a.id}`;
    item.description = eff.label;
    item.tooltip = eff.detail ? `${eff.label}\n\n${eff.detail}` : eff.label;
    // The green check only for an agent that is screened with a key known to work.
    item.iconPath =
      eff.level === "protected"
        ? new vscode.ThemeIcon("pass", new vscode.ThemeColor("testing.iconPassed"))
        : eff.level === "absent"
          ? new vscode.ThemeIcon("circle-slash")
          : eff.level === "unverified"
            ? new vscode.ThemeIcon("question")
            : new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    item.contextValue = KNOWN_AGENT_IDS.has(a.id) && eff.connectable ? "agent connectable" : "agent";
    return item;
  }
}

/** Wires the Agents view, its commands and refreshes into the extension. */
export function registerAgents(
  context: vscode.ExtensionContext,
  deps: {
    log: (m: string) => void;
    getKey: () => Thenable<string | undefined>;
    signedIn: () => Promise<boolean>;
    /** Checks a key without using quota. */
    keyStatus: (key: string) => Promise<"works" | "rejected" | "unknown">;
  },
): void {
  const installer = new Installer(context.globalStorageUri.fsPath, deps.log);
  const tree = new AgentsTree();
  const view = vscode.window.createTreeView("agentguards.agents", { treeDataProvider: tree });
  context.subscriptions.push(view);

  // The saved key's status, checked without quota; re-checked at most every 10 minutes.
  let savedCache: { key: string; status: SavedKey; at: number } | undefined;
  async function savedKeyStatus(): Promise<SavedKey> {
    const key = await installerKey();
    if (!key) return "none";
    if (savedCache && savedCache.key === key && Date.now() - savedCache.at < 10 * 60_000) {
      return savedCache.status;
    }
    const status = await deps.keyStatus(key).catch(() => "unknown" as const);
    savedCache = { key, status, at: Date.now() };
    return status;
  }

  // Agents' own keys are checked (read-only, no quota) on a manual refresh, after
  // Connect, and otherwise at most every 10 minutes — like the saved key.
  const KEY_CHECK_MS = 10 * 60_000;
  let lastKeyCheck = 0;
  let lastChecked: DoctorReport | undefined;

  let lastRefresh = 0;
  let refreshing: Promise<void> | undefined;
  let again: Promise<void> | undefined;
  function refresh(force = false): Promise<void> {
    // A forced refresh (after Connect) must read the state after it, not join one that
    // started before it finished — but any number of them share one follow-up run.
    if (refreshing) {
      if (!force) return refreshing;
      again ??= refreshing.then(() => {
        again = undefined;
        return refresh(true);
      });
      return again;
    }
    if (!force && Date.now() - lastRefresh < 60_000) return Promise.resolve();
    lastRefresh = Date.now();
    if (tree.status.kind === "unknown") tree.set({ kind: "checking" });
    const checkKeys = force || Date.now() - lastKeyCheck >= KEY_CHECK_MS;
    const run = Promise.all([installer.status(checkKeys), savedKeyStatus()])
      .then(([s, saved]) => {
        if (s.kind === "ok" && checkKeys) {
          lastKeyCheck = Date.now();
          lastChecked = s.report;
        } else if (s.kind === "ok") {
          s = { kind: "ok", report: withKeyStatus(s.report, lastChecked) };
        }
        tree.set(s, saved);
        const n =
          s.kind === "ok"
            ? s.report.agents.filter((a) => effectiveState(s.report, a, saved).level === "unprotected").length
            : 0;
        view.badge = n ? { value: n, tooltip: `${n} coding agent(s) not protected` } : undefined;
      })
      .catch((e) => {
        tree.set({ kind: "unavailable", message: String(e?.message ?? e) });
        view.badge = undefined;
      })
      .finally(() => (refreshing = undefined));
    refreshing = run;
    // A progress bar on the view, so a refresh that changes nothing is still visible.
    void vscode.window.withProgress({ location: { viewId: "agentguards.agents" } }, () => run);
    return refreshing;
  }

  async function connect(ids: string[]): Promise<void> {
    if (!(await deps.signedIn())) {
      const c = await vscode.window.showInformationMessage(
        "Sign in to AgentGuards first: the agents use the same account.",
        "Sign In",
      );
      if (c) await vscode.commands.executeCommand("agentguards.signIn");
      return;
    }
    const s = tree.status;
    const names =
      s.kind === "ok" ? s.report.agents.filter((a) => ids.includes(a.id)).map((a) => a.name) : ids;
    const ok = await vscode.window.showInformationMessage(
      `Connect ${names.join(" and ")} to AgentGuards?`,
      {
        modal: true,
        detail:
          "This runs the AgentGuards installer in a terminal. It installs the AgentGuards plugin into each agent " +
          "(through the agent's own plugin command). Your agents use the AgentGuards key saved in " +
          "~/.agentguards/credentials.json; if there isn't one, the key this editor is signed in with is saved " +
          "there, readable only by you. Prompts, commands and fetched web content are then screened, and each " +
          "screening uses a request from your plan.",
      },
      "Connect",
    );
    if (ok !== "Connect") return;
    let code: number;
    try {
      const rejected = savedKeyRejected(tree.status.kind === "ok" ? tree.status.report : undefined, tree.saved);
      code = await installer.install(ids, await deps.getKey(), rejected);
      savedCache = undefined; // the installer may have saved a new key
    } catch (err) {
      void vscode.window.showErrorMessage(`AgentGuards: ${(err as Error).message}`);
      return;
    }
    await refresh(true);
    if (code === 0) {
      void vscode.window.showInformationMessage(
        `AgentGuards: ${names.join(" and ")} connected. Restart any open sessions so they load it.`,
      );
    } else {
      void vscode.window.showWarningMessage(
        "AgentGuards: the installer reported a problem — see the AgentGuards terminal for details.",
      );
    }
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("agentguards.refreshAgents", () => refresh(true)),
    vscode.commands.registerCommand("agentguards.connectAgent", (node?: Node) => {
      if (node?.kind === "agent") return connect([node.agent.id]);
    }),
    vscode.commands.registerCommand("agentguards.connectAllAgents", async () => {
      await refresh(true);
      const s = tree.status;
      if (s.kind !== "ok") return;
      const ids = connectable(s.report, tree.saved)
        .map((a) => a.id)
        .filter((id) => KNOWN_AGENT_IDS.has(id));
      if (!ids.length) {
        const present = s.report.agents.filter((a) => a.state !== "not_found");
        const allProtected =
          present.length > 0 && present.every((a) => effectiveState(s.report, a, tree.saved).level === "protected");
        void vscode.window.showInformationMessage(
          allProtected
            ? "AgentGuards: every coding agent found on this computer is already protected."
            : present.length
              ? "AgentGuards: Connect can't fix what's left — hover over each agent in the Coding Agents view to see what to do."
              : "AgentGuards: no Claude Code or Codex CLI found on this computer.",
        );
        return;
      }
      return connect(ids);
    }),
    view.onDidChangeVisibility((e) => {
      if (e.visible) void refresh();
    }),
    vscode.window.onDidChangeWindowState((w) => {
      if (w.focused && view.visible) void refresh();
    }),
  );
  if (view.visible) void refresh();
}
