import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import { registerAgents } from "./agents";
import { Auth } from "./auth";
import { AgentGuardsClient, ApiError, AuthError, QuotaExceededError } from "./core/api";
import {
  currentPlatform,
  displayName,
  refKey,
  storeFor,
  toRef,
  type ExtensionRef,
  type InstalledExtension,
} from "./core/inventory";
import { mergeInstalled, readOnDisk, type OnDiskExtension } from "./core/ondisk";
import { isIgnored, notification, Scanner, SEVERITY_ORDER, type StoredResult } from "./core/scanner";
import { FileStore, Leader } from "./core/store";
import { ExtensionsTree, isFlagged, type Row } from "./tree";

const DASHBOARD_URL = "https://agentguards.co/dashboard";
const BILLING_URL = "https://agentguards.co/dashboard/billing";
const STARTUP_DELAY_MS = 8_000;
const CHANGE_DEBOUNCE_MS = 3_000;
const PERIODIC_MS = 60 * 60_000;
const HEARTBEAT_MS = 30_000;
const REFRESH_MS = 20_000;
const QUOTA_NOTICE_EVERY_MS = 24 * 60 * 60_000;
const FINAL = new Set(["malicious", "high", "medium", "clean"]);

// Shared by every window (files in global storage; see core/store.ts).
const F_RESULTS = "results.json";
const F_IGNORED = "ignored.json"; // ["<refKey>|<verdict>", ...]
const F_STATUS = "status.json"; // the leader's last check outcome
const F_REQUEST = "check-request.json"; // a check asked for by a window that isn't leading
const D_WINDOWS = "windows"; // windows/<id>.json: each window's installed extensions
// Per user, not per window: globalState is fine.
const K_SIGNIN_PROMPTED = "signInPrompted";
const K_QUOTA_NOTICE = "quotaNoticeAt";

interface WindowInventory {
  at: number;
  refs: ExtensionRef[];
}

interface SharedStatus {
  running: boolean;
  quota: boolean;
  authFailed?: string;
  lastError?: string;
  at: number;
}

export function activate(context: vscode.ExtensionContext): void {
  const out = vscode.window.createOutputChannel("AgentGuards", { log: true });
  const log = (m: string) => out.info(m);
  const selfId = context.extension.id.toLowerCase();
  const version = String(context.extension.packageJSON.version ?? "0");
  const state = context.globalState;
  const config = () => vscode.workspace.getConfiguration("agentguards");
  const store = new FileStore(context.globalStorageUri.fsPath);
  const leader = new Leader(context.globalStorageUri.fsPath);

  const client = (): AgentGuardsClient =>
    new AgentGuardsClient({
      baseUrl: config().get<string>("apiUrl") || "https://prod.agentguards.co",
      clientHeader: `vscode/ts/${version}`,
      getKey: (): Promise<string | undefined> => Promise.resolve(auth.getKey()),
    });
  const auth: Auth = new Auth(context.secrets, client, log);

  const tree = new ExtensionsTree();
  const view = vscode.window.createTreeView("agentguards.extensions", {
    treeDataProvider: tree,
    showCollapseAll: true,
  });
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.name = "AgentGuards";
  status.show();
  context.subscriptions.push(out, view, status);

  registerAgents(context, {
    log,
    getKey: () => auth.getKey(),
    signedIn: () => auth.isSignedIn(),
    keyStatus: (key) => client().keyStatus(key),
  });

  // ---- inventory -----------------------------------------------------------------

  const musl = process.platform === "linux" && fs.existsSync("/etc/alpine-release");
  const platform = currentPlatform(process.platform, process.arch, musl);
  const builtinRoot = path.join(vscode.env.appRoot, "extensions") + path.sep;

  // Where this editor installs extensions: the folder this extension was installed into.
  // Its extensions.json also lists extensions that aren't running yet (see ondisk.ts).
  const extensionsDir =
    context.extensionUri.scheme === "file" ? path.dirname(context.extensionUri.fsPath) : undefined;
  let diskCache: { stamp: string; list: OnDiskExtension[] } | undefined;
  function onDisk(): OnDiskExtension[] {
    if (!extensionsDir) return [];
    const mtime = (f: string) => {
      try {
        return String(fs.statSync(path.join(extensionsDir, f)).mtimeMs);
      } catch {
        return "-";
      }
    };
    const stamp = `${mtime("extensions.json")}|${mtime(".obsolete")}`;
    if (diskCache?.stamp !== stamp) diskCache = { stamp, list: readOnDisk(extensionsDir) };
    return diskCache.list;
  }

  function installed(): { ext: InstalledExtension; ref: ExtensionRef | null; running: boolean }[] {
    const source = storeFor(vscode.env.appName, config().get<string>("store"));
    const running = vscode.extensions.all
      .filter((e) => {
        if (e.id.toLowerCase() === selfId) return false;
        if (e.packageJSON?.isBuiltin === true) return false;
        return !e.extensionUri.fsPath.startsWith(builtinRoot);
      })
      .map((e): InstalledExtension => {
        const pj = e.packageJSON ?? {};
        return {
          id: e.id,
          version: String(pj.version ?? ""),
          displayName: displayName(pj.displayName, e.id),
          targetPlatform: pj.__metadata?.targetPlatform ?? pj.targetPlatform,
        };
      });
    return mergeInstalled(running, onDisk(), selfId).map(({ ext, running }) => ({
      ext,
      ref: toRef(ext, source, platform),
      running,
    }));
  }
  const ownRefs = () =>
    installed()
      .map((x) => x.ref)
      .filter((r): r is ExtensionRef => r !== null);

  // Windows can differ (an extension enabled in one workspace, disabled in another),
  // so each window publishes its list and the leader checks the union.
  const inventoryFile = () => path.join(D_WINDOWS, `${leader.id}.json`);
  const publishInventory = () =>
    store.writeJson(inventoryFile(), { at: Date.now(), refs: ownRefs() } satisfies WindowInventory);
  let others: ExtensionRef[] = [];
  async function loadOthers(): Promise<void> {
    const all = await store.readAll<WindowInventory>(D_WINDOWS);
    const now = Date.now();
    others = all
      .filter(({ value: w }) => now - w.at < 3 * HEARTBEAT_MS && Array.isArray(w.refs))
      .flatMap(({ value: w }) => w.refs);
    // Windows that crashed or were killed never removed theirs.
    for (const { name, value: w } of all) {
      if (!(now - w.at < 20 * HEARTBEAT_MS)) void store.remove(path.join(D_WINDOWS, name));
    }
  }
  const installedRefs = () => {
    const byKey = new Map<string, ExtensionRef>();
    for (const r of [...others, ...ownRefs()]) byKey.set(refKey(r), r);
    return [...byKey.values()];
  };

  // ---- shared state ----------------------------------------------------------------

  const loadResults = () => store.readJson<Record<string, StoredResult>>(F_RESULTS, {});
  const loadIgnored = () => store.readJson<string[]>(F_IGNORED, []);
  let leading = false;
  let running = false;
  // When the plan's quota was last reported used up. Shown for a day: nothing may be
  // sent for longer (results are good for 1-7 days), and an upgrade must clear it.
  let quotaHitAt = 0;
  const quotaHit = () => Date.now() - quotaHitAt < QUOTA_NOTICE_EVERY_MS;
  let authFailed: string | undefined;
  let lastError: string | undefined;

  async function publishStatus(): Promise<void> {
    if (!leading) return;
    const s: SharedStatus = { running, quota: quotaHit(), authFailed, lastError, at: Date.now() };
    await store.writeJson(F_STATUS, s).catch(() => undefined);
  }

  // ---- view + status bar -------------------------------------------------------------

  let refreshing: Promise<void> | undefined;
  function refresh(): Promise<void> {
    // One refresh at a time; a call made meanwhile runs after it.
    const next = (refreshing ?? Promise.resolve())
      .then(doRefresh)
      .catch((e) => log(`refresh: ${e}`));
    refreshing = next;
    return next;
  }

  async function doRefresh(): Promise<void> {
    const signedIn = await auth.isSignedIn();
    void vscode.commands.executeCommand("setContext", "agentguards.signedIn", signedIn);
    if (!signedIn) {
      tree.setRows([]); // empty → the view shows its Sign In welcome
      renderStatus([], false, undefined);
      return;
    }
    const [stored, ignored] = await Promise.all([loadResults(), loadIgnored()]);
    const rows: Row[] = installed().map(({ ext, ref, running }) => {
      const key = ref ? refKey(ref) : `local:${ext.id.toLowerCase()}@${ext.version}`;
      const result = ref ? stored[key] : undefined;
      return {
        key,
        id: ext.id,
        name: ext.displayName,
        version: ext.version,
        result,
        ignored: !!result && isIgnored(ignored, key, result.verdict),
        uncheckable: !ref,
        notRunning: !running,
      };
    });
    tree.setRows(rows);
    const shared = leading
      ? undefined
      : await store.readJson<SharedStatus | undefined>(F_STATUS, undefined);
    renderStatus(rows, true, shared);
    void notifySweep(rows);
  }

  function renderStatus(rows: Row[], signedIn: boolean, shared: SharedStatus | undefined): void {
    status.backgroundColor = undefined;
    status.command = "agentguards.extensions.focus";
    if (!signedIn) {
      status.text = "$(shield) AgentGuards: Sign in";
      status.tooltip = "Sign in to check your extensions for malware";
      status.command = "agentguards.signIn";
      return;
    }
    // The leader knows its own state; other windows read what it last published.
    const isRunning = leading ? running : !!shared?.running;
    const quota = leading ? quotaHit() : !!shared?.quota;
    const authErr = leading ? authFailed : shared?.authFailed;
    const err = leading ? lastError : shared?.lastError;

    const flagged = rows.filter((r) => !r.ignored && isFlagged(r.result?.verdict));
    const severe = flagged.some(
      (r) => r.result?.verdict === "malicious" || r.result?.verdict === "high",
    );
    if (flagged.length) {
      status.text = `$(warning) AgentGuards: ${flagged.length} flagged`;
      status.tooltip = flagged.map((r) => `${r.name}: ${r.result?.reason}`).join("\n");
      status.backgroundColor = new vscode.ThemeColor(
        severe ? "statusBarItem.errorBackground" : "statusBarItem.warningBackground",
      );
    } else if (authErr) {
      // Checks are failing: never look like the protected state.
      status.text = "$(warning) AgentGuards: sign in again";
      status.tooltip = `Extensions aren't being checked: ${authErr}`;
      status.command = "agentguards.signIn";
      status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else if (quota) {
      status.text = "$(warning) AgentGuards: quota used up";
      status.tooltip =
        "Your plan's request quota is used up. Known malware is still flagged; other new extensions aren't checked.";
      status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else if (err) {
      status.text = "$(warning) AgentGuards: not checking";
      status.tooltip = `The last check failed: ${err}. Retrying automatically.`;
      status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else if (isRunning) {
      status.text = "$(sync~spin) AgentGuards";
      status.tooltip = "Checking extensions…";
    } else {
      const checked = rows.filter((r) => r.result && FINAL.has(r.result.verdict)).length;
      status.text = "$(shield) AgentGuards";
      status.tooltip =
        checked === rows.length
          ? `All ${rows.length} extensions checked, nothing flagged`
          : `${checked} of ${rows.length} extensions checked, nothing flagged; the rest couldn't be checked yet`;
    }
  }

  // ---- notifications ---------------------------------------------------------------
  //
  // Shown only by the focused window, and each "extension@version is <verdict>" only
  // once across all windows (FileStore.claimOnce). A warning is claimed right before
  // it is shown, so one never shown (window reloaded mid-sequence) is still unclaimed
  // and appears on the next sweep.

  let sweeping = false;
  let sweepAgain = false;
  const pendingReload: string[] = [];

  async function notifySweep(rows: Row[]): Promise<void> {
    if (!vscode.window.state.focused) return;
    if (sweeping) {
      sweepAgain = true;
      return;
    }
    sweeping = true;
    try {
      const notifyMedium = config().get<boolean>("notifyMedium", true);
      const due = rows
        .filter((r) => r.result && notification(r.result, { notifyMedium, ignored: r.ignored }))
        .sort((a, b) => SEVERITY_ORDER[a.result!.verdict] - SEVERITY_ORDER[b.result!.verdict]);
      const toasts: Row[] = [];
      try {
        for (const row of due) {
          const r = row.result!;
          const kind = notification(r, { notifyMedium, ignored: row.ignored });
          try {
            if (!(await store.claimOnce(`${row.key}|${r.verdict}`))) continue;
          } catch (err) {
            log(`notify claim: ${(err as Error).message}`);
            continue; // unclaimed: retried on the next sweep
          }
          if (kind === "toast") toasts.push(row);
          else await showModal(row);
        }
      } finally {
        // Claimed toasts are always shown, even if a modal above failed.
        if (toasts.length) showToasts(toasts);
      }
      if (pendingReload.length) await reloadPrompt();
    } catch (err) {
      log(`notify: ${(err as Error).message}`);
    } finally {
      sweeping = false;
    }
    if (sweepAgain) {
      sweepAgain = false;
      void refresh();
    }
  }

  async function reloadPrompt(): Promise<void> {
    const names = pendingReload.splice(0).join(", ");
    const c = await vscode.window.showInformationMessage(
      `AgentGuards: ${names} uninstalled. It keeps running in every open window until that window reloads — reload each one, or restart VS Code.`,
      "Reload This Window",
    );
    if (c === "Reload This Window") {
      await vscode.commands.executeCommand("workbench.action.reloadWindow");
    }
  }

  async function showModal(row: Row): Promise<void> {
    const r = row.result!;
    const what = r.verdict === "malicious" ? "looks malicious" : "is high risk";
    const findings = (r.findings ?? []).slice(0, 5).map((f) => `• [${f.severity}] ${f.title}`);
    const choice = await vscode.window.showWarningMessage(
      `AgentGuards: ${row.name} ${what}`,
      { modal: true, detail: [r.reason, "", ...findings].join("\n") },
      "Uninstall",
      "Show Details",
      "Ignore",
    );
    if (choice === "Uninstall") {
      // The reload prompt waits until every pending warning has been shown.
      if (await uninstall(row)) pendingReload.push(row.name);
    } else if (choice === "Show Details") await reveal(row.key);
    else if (choice === "Ignore") await setIgnored(row, true);
  }

  function showToasts(rows: Row[]): void {
    const first = rows[0];
    const text =
      rows.length === 1
        ? `AgentGuards: ${first.name} — ${first.result!.reason}`
        : `AgentGuards: ${rows.length} extensions have medium-risk findings, such as bundled code with known vulnerabilities.`;
    const actions = rows.length === 1 ? ["Show Details", "Ignore"] : ["Show Details"];
    void vscode.window.showWarningMessage(text, ...actions).then(async (c) => {
      if (c === "Show Details") await reveal(first.key);
      if (c === "Ignore") await setIgnored(first, true);
    });
  }

  async function reveal(key: string): Promise<void> {
    await vscode.commands.executeCommand("agentguards.extensions.focus");
    const node = tree.nodeFor(key);
    if (node) await view.reveal(node, { expand: true, select: true, focus: true });
  }

  async function setIgnored(row: Row, on: boolean): Promise<void> {
    const ignored = (await loadIgnored()).filter((e) => !e.startsWith(`${row.key}|`));
    if (on && row.result) ignored.push(`${row.key}|${row.result.verdict}`);
    await store.writeJson(F_IGNORED, ignored);
    // "Warn Me Again" means the warning shows again, not only the flag in the view.
    if (!on && row.result) await store.unclaim(`${row.key}|${row.result.verdict}`);
    await refresh();
  }

  async function uninstall(row: Row): Promise<boolean> {
    try {
      await vscode.commands.executeCommand("workbench.extensions.uninstallExtension", row.id);
      log(`uninstalled ${row.id}`);
      return true;
    } catch (err) {
      void vscode.window.showErrorMessage(
        `AgentGuards: could not uninstall ${row.name}: ${(err as Error).message}. Remove it from the Extensions view.`,
      );
      return false;
    }
  }

  // ---- checking (one window at a time: the leader) ----------------------------------

  let generation = 0;
  let rerun: { force: boolean } | undefined;
  let wake: (() => void) | undefined;
  let authNoticeShown = false;

  const scanner = new Scanner({
    scan: (refs) => client().scan(refs, vscode.env.appName),
    load: loadResults,
    save: (r) => store.writeJson(F_RESULTS, r),
    onResults: () => void refresh(),
    onQuota: (exhausted) => {
      if (exhausted && !quotaHit()) void quotaNotice();
      quotaHitAt = exhausted ? Date.now() : 0;
    },
    now: () => Date.now(),
    sleep: (ms) =>
      new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(timer);
          wake = undefined;
          resolve();
        };
        const timer = setTimeout(done, ms);
        wake = done;
      }),
    log,
  });

  async function becomeLeader(): Promise<boolean> {
    const was = leading;
    try {
      leading = await leader.acquire();
    } catch (err) {
      log(`lock: ${(err as Error).message}`);
      leading = false;
    }
    if (leading !== was) {
      log(leading ? "This window now runs the checks" : "Another window now runs the checks");
    }
    return leading;
  }

  /**
   * @param nudge in a window that isn't leading, ask the leader to check (true for an
   *   install, sign-in or Check Now; false for the hourly timer, which the leader runs
   *   itself).
   */
  async function check(force = false, nudge = true): Promise<void> {
    if (running) {
      // The poll loop re-reads the extension list each round; wake it now.
      rerun = { force: force || (rerun?.force ?? false) };
      wake?.();
      return;
    }
    // Claimed before the first await and cleared only below, so two calls at once
    // can't both start a run.
    running = true;
    try {
      if (!(await auth.isSignedIn())) return;
      await publishInventory().catch((e) => log(`inventory: ${e}`));
      if (await becomeLeader()) {
        await runChecks(force);
      } else if (nudge || force) {
        // The leader checks every window's extensions; tell it there's something new.
        // Merge, so a plain nudge can't erase a pending Check Now.
        const prev = await store.readJson<{ at?: number; force?: boolean }>(F_REQUEST, {});
        const prevForce = prev.force === true && Date.now() - (prev.at ?? 0) < 2 * HEARTBEAT_MS;
        await store.writeJson(F_REQUEST, { at: Date.now(), force: force || prevForce });
      }
    } catch (err) {
      log(`check: ${(err as Error).message}`);
    } finally {
      running = false;
      void publishStatus();
      void refresh();
      if (rerun) {
        const next = rerun;
        rerun = undefined;
        void check(next.force);
      }
    }
  }

  async function runChecks(force: boolean): Promise<void> {
    const gen = ++generation;
    await loadOthers();
    await publishStatus();
    void refresh();
    try {
      await scanner.run(installedRefs, {
        force,
        isCancelled: () => gen !== generation || !leading,
      });
      lastError = undefined;
      authFailed = undefined;
    } catch (err) {
      await handleError(err);
    }
  }

  async function quotaNotice(): Promise<void> {
    const last = state.get<number>(K_QUOTA_NOTICE, 0);
    if (Date.now() - last < QUOTA_NOTICE_EVERY_MS) return;
    await state.update(K_QUOTA_NOTICE, Date.now());
    const c = await vscode.window.showWarningMessage(
      "AgentGuards: your plan's request quota is used up. Known malware is still flagged, but other new extensions aren't checked.",
      "View Plans",
    );
    if (c) await vscode.env.openExternal(vscode.Uri.parse(BILLING_URL));
  }

  async function handleError(err: unknown): Promise<void> {
    if (err instanceof QuotaExceededError) {
      quotaHitAt = Date.now();
      log(`quota: ${err.message}`);
      void quotaNotice();
    } else if (err instanceof AuthError) {
      if (!(await auth.isSignedIn())) return; // signed out mid-check: nothing to report
      authFailed = err.message;
      log(`auth: ${err.message}`);
      if (!authNoticeShown) {
        authNoticeShown = true;
        void vscode.window
          .showWarningMessage(
            `AgentGuards: your API key was not accepted (${err.message}). Sign in again to keep checking extensions.`,
            "Sign In",
          )
          .then((c) => c && vscode.commands.executeCommand("agentguards.signIn"));
      }
    } else {
      lastError = err instanceof ApiError ? err.message : String((err as Error)?.message ?? err);
      log(`check failed: ${lastError}`);
    }
  }

  let handledRequest = 0;
  async function heartbeat(): Promise<void> {
    if (!(await auth.isSignedIn())) return;
    await publishInventory().catch(() => undefined);
    const wasLeading = leading;
    if (!(await becomeLeader())) return void refresh();
    await publishStatus();
    await loadOthers();
    const req = await store.readJson<{ at?: number; force?: boolean }>(F_REQUEST, {});
    // A request is for whoever leads now: one older than two heartbeats was for a
    // previous leader (handled, or lost with its window) and isn't replayed.
    const fresh = typeof req.at === "number" && Date.now() - req.at < 2 * HEARTBEAT_MS;
    const asked = fresh && req.at! > handledRequest;
    if (typeof req.at === "number") handledRequest = Math.max(handledRequest, req.at);
    if (asked || !wasLeading) void check(asked && req.force === true); // queued if running
  }

  // ---- commands ----------------------------------------------------------------------

  type TreeArg = { kind: "ext"; row: Row } | undefined;
  context.subscriptions.push(
    vscode.commands.registerCommand("agentguards.signIn", async () => {
      if (await auth.signIn()) {
        authNoticeShown = false;
        authFailed = undefined;
        void check(true);
      }
    }),
    vscode.commands.registerCommand("agentguards.signOut", async () => {
      generation++;
      await auth.signOut();
      await refresh();
    }),
    vscode.commands.registerCommand("agentguards.scanNow", () => check(true)),
    vscode.commands.registerCommand("agentguards.uninstall", async (arg: TreeArg) => {
      if (arg?.kind !== "ext") return;
      const ok = await vscode.window.showWarningMessage(
        `Uninstall ${arg.row.name}?`,
        { modal: true, detail: arg.row.result?.reason },
        "Uninstall",
      );
      if (ok === "Uninstall" && (await uninstall(arg.row))) await queueReloadPrompt(arg.row.name);
    }),
    vscode.commands.registerCommand("agentguards.ignore", (arg: TreeArg) =>
      arg?.kind === "ext" ? setIgnored(arg.row, true) : undefined,
    ),
    vscode.commands.registerCommand("agentguards.unignore", (arg: TreeArg) =>
      arg?.kind === "ext" ? setIgnored(arg.row, false) : undefined,
    ),
    vscode.commands.registerCommand("agentguards.openDashboard", () =>
      vscode.env.openExternal(vscode.Uri.parse(DASHBOARD_URL)),
    ),
    vscode.commands.registerCommand("agentguards.showLog", () => out.show()),
  );

  async function queueReloadPrompt(name: string): Promise<void> {
    pendingReload.push(name);
    if (!sweeping) await reloadPrompt();
  }

  // ---- triggers ----------------------------------------------------------------------

  let debounce: NodeJS.Timeout | undefined;
  const extensionsChanged = () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      void refresh();
      void check();
    }, CHANGE_DEBOUNCE_MS);
  };
  if (extensionsDir) {
    // An install VS Code won't start until a restart doesn't fire onDidChange; the
    // editor still writes it to extensions.json, so watch that too.
    const watcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(vscode.Uri.file(extensionsDir), "{extensions.json,.obsolete}"),
    );
    context.subscriptions.push(
      watcher,
      watcher.onDidChange(extensionsChanged),
      watcher.onDidCreate(extensionsChanged),
      watcher.onDidDelete(extensionsChanged),
    );
  }
  context.subscriptions.push(
    vscode.extensions.onDidChange(extensionsChanged),
    auth.onDidChange((signedIn: boolean) => {
      if (!signedIn) generation++;
      void refresh();
      if (signedIn) void check(); // in every window; only the leader sends anything
    }),
    vscode.window.onDidChangeWindowState((s) => {
      if (s.focused) void refresh();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("agentguards")) {
        void refresh();
        if (e.affectsConfiguration("agentguards.store")) void check();
      }
    }),
  );
  const timers = [
    setInterval(() => void check(false, false), PERIODIC_MS),
    setInterval(() => void heartbeat(), HEARTBEAT_MS),
    // Other windows' results and status reach this one through the shared files.
    setInterval(() => {
      if (vscode.window.state.focused && !running) void refresh();
    }, REFRESH_MS),
  ];
  context.subscriptions.push({
    dispose: () => {
      timers.forEach(clearInterval);
      clearTimeout(debounce);
      generation++;
      void leader.release();
      void store.remove(inventoryFile());
    },
  });

  log(
    `AgentGuards ${version} in ${vscode.env.appName}: store ${storeFor(vscode.env.appName, config().get<string>("store"))}, platform ${platform ?? "unknown"}`,
  );
  void refresh();
  const startup = setTimeout(async () => {
    if (await auth.isSignedIn()) return void check();
    if (state.get<boolean>(K_SIGNIN_PROMPTED)) return;
    await state.update(K_SIGNIN_PROMPTED, true);
    const c = await vscode.window.showInformationMessage(
      "AgentGuards checks your extensions for malware and vulnerable code. Sign in to start.",
      "Sign In",
      "Later",
    );
    if (c === "Sign In") await vscode.commands.executeCommand("agentguards.signIn");
  }, STARTUP_DELAY_MS);
  context.subscriptions.push({ dispose: () => clearTimeout(startup) });
}

export function deactivate(): void {}
