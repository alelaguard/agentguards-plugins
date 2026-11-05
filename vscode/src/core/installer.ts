// The AgentGuards installer (the `agentguards` CLI): which release asset this machine
// needs, checking a download against the release's SHA256SUMS, and reading
// `agentguards doctor --json --offline --check-agent-keys`. No VS Code imports.
//
// Connecting an agent runs this same installer — the hooks are never reimplemented
// here, so there is one implementation of "install AgentGuards into Claude Code".

import { createHash } from "node:crypto";

export const RELEASE_BASE = "https://github.com/alelaguard/agentguards-plugins/releases/latest/download";

/** The release asset for this machine, as install.sh / install.ps1 name it. */
export function assetName(platform: string, arch: string): string | undefined {
  const a = arch === "x64" ? "amd64" : arch === "arm64" ? "arm64" : undefined;
  if (!a) return undefined;
  if (platform === "linux") return `agentguards_linux_${a}`;
  if (platform === "darwin") return `agentguards_darwin_${a}`;
  if (platform === "win32") return `agentguards_windows_${a}.exe`;
  return undefined;
}

/** The expected SHA-256 for `asset` from a SHA256SUMS file (sha256sum format). */
export function expectedSha256(sums: string, asset: string): string | undefined {
  for (const line of sums.split(/\r?\n/)) {
    const m = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line);
    if (m && m[2] === asset) return m[1].toLowerCase();
  }
  return undefined;
}

export function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Throws unless `data` is exactly what the release lists for `asset`. */
export function verifyDownload(data: Uint8Array, sums: string, asset: string): void {
  const want = expectedSha256(sums, asset);
  if (!want) throw new Error(`no checksum for ${asset} in the release's SHA256SUMS`);
  if (sha256(data) !== want) throw new Error(`checksum mismatch for ${asset} — refusing to run it`);
}

export type AgentState = "enabled" | "disabled" | "not_installed" | "error" | "not_found";

export interface DoctorAgent {
  id: string;
  name: string;
  state: AgentState;
  /** Installed but older than the installer requires (`install` upgrades it). */
  outdated?: boolean;
  /** Where this agent's hook gets its key; never the key itself. */
  key_source?: "claude_settings" | "claude_plugin" | "codex_token" | "env" | "saved" | string;
  /** False when the agent has no key to send (or its own key file holds none). */
  key_found?: boolean;
  /** That key, checked with a read-only request that uses no quota. */
  key_status?: KeyStatus;
  error?: string;
}

/** other_server: the agent's hook uses another AgentGuards server; its key isn't checked. */
export type KeyStatus = "works" | "rejected" | "unknown" | "other_server";
const KEY_STATUSES = new Set<KeyStatus>(["works", "rejected", "unknown", "other_server"]);

export interface DoctorReport {
  version: string;
  key_found: boolean;
  hook_runtime_ok: boolean;
  codex_key_override: boolean;
  agents: DoctorAgent[];
  checks: { ok: boolean; message: string }[];
}

const STATES = new Set<AgentState>(["enabled", "disabled", "not_installed", "error", "not_found"]);

/**
 * The report from `doctor --json`, or undefined when the output isn't one — an
 * installer older than the --json flag prints usage text and exits 2.
 */
export function parseDoctor(stdout: string): DoctorReport | undefined {
  let v: any;
  try {
    v = JSON.parse(stdout);
  } catch {
    return undefined;
  }
  if (!v || typeof v !== "object" || !Array.isArray(v.agents)) return undefined;
  const agents: DoctorAgent[] = v.agents
    .filter((a: any) => typeof a?.id === "string" && typeof a?.name === "string")
    .map((a: any) => ({
      id: a.id,
      name: a.name,
      state: STATES.has(a.state) ? a.state : "error",
      outdated: a.outdated === true,
      key_source: typeof a.key_source === "string" ? a.key_source : undefined,
      key_found: a.key_found === true,
      key_status: KEY_STATUSES.has(a.key_status) ? a.key_status : undefined,
      error: typeof a.error === "string" ? a.error : undefined,
    }));
  return {
    version: String(v.version ?? ""),
    key_found: v.key_found === true,
    // Missing means "not known to be fine": never assume a working runtime.
    hook_runtime_ok: v.hook_runtime_ok === true,
    codex_key_override: v.codex_key_override === true,
    agents,
    checks: Array.isArray(v.checks)
      ? v.checks
          .filter((c: any) => typeof c?.message === "string")
          .map((c: any) => ({ ok: c.ok === true, message: c.message }))
      : [],
  };
}

/** What the extension knows about the saved key (~/.agentguards/credentials.json). */
export type SavedKey = "works" | "rejected" | "unknown" | "none";

export interface Effective {
  /**
   * protected: screened, with a key known to work (the only level shown green).
   * unverified: set up, but its key couldn't be checked from here.
   * unprotected: not screened. absent: the agent isn't on this computer.
   */
  level: "protected" | "unverified" | "unprotected" | "absent";
  label: string;
  /** Running the installer for this agent would fix it. */
  connectable: boolean;
  detail?: string;
}

/**
 * What to show for an agent. "Plugin enabled" is not "protected": the hook also needs
 * a key that works, a runtime (python3) to run, and an up-to-date plugin. The green
 * "Protected" is only for an agent whose key was checked and works.
 */
export function effectiveState(report: DoctorReport, a: DoctorAgent, saved: SavedKey): Effective {
  switch (a.state) {
    case "not_found":
      return { level: "absent", label: "Not installed on this computer", connectable: false };
    case "not_installed":
      return { level: "unprotected", label: "Not connected", connectable: true };
    case "disabled":
      return { level: "unprotected", label: "Installed but disabled — not protected", connectable: true };
    case "error":
      return { level: "unprotected", label: "Couldn't check", connectable: false, detail: a.error };
  }
  if (!a.key_found) {
    if (a.key_source === "codex_token") {
      return {
        level: "unprotected",
        label: "Its key file holds no valid key — not protected",
        connectable: false,
        detail: "Codex sends ~/.codex/agentguards_token instead of the saved key. Delete that file or put a working key in it.",
      };
    }
    return { level: "unprotected", label: "No API key — not protected", connectable: true };
  }
  if (!report.hook_runtime_ok) {
    const why = report.checks.find((c) => !c.ok && /python/i.test(c.message))?.message;
    return { level: "unprotected", label: "python3 missing — not protected", connectable: false, detail: why };
  }
  if (a.outdated) {
    // A structured field, not message matching: rewording a check can't flip this.
    return {
      level: "unprotected",
      label: "Plugin out of date — not fully protected",
      connectable: true,
      detail: "Connect upgrades it.",
    };
  }
  const where = KEY_PLACES[a.key_source ?? ""] ?? "its own settings";
  if (a.key_status === "other_server") {
    return {
      level: "unverified",
      label: "Set up — uses another AgentGuards server",
      connectable: false,
      detail: "Its settings point it at a different AgentGuards server (AGENTGUARDS_URL), so its key isn't checked here.",
    };
  }
  if (a.key_source === "saved") {
    // The installer's check of the key, else the extension's own check of it.
    const status = a.key_status ?? (saved === "none" ? "unknown" : saved);
    if (status === "works") return { level: "protected", label: "Protected", connectable: false };
    if (status === "rejected") {
      return {
        level: "unprotected",
        label: "API key rejected — not protected",
        connectable: true,
        detail: "The saved key was revoked or deleted. Connect saves the key this editor is signed in with.",
      };
    }
    return {
      level: "unverified",
      label: "Set up — couldn't verify the key",
      connectable: false,
      detail: "AgentGuards couldn't be reached to check the saved key. It is checked again on the next refresh.",
    };
  }
  if (a.key_status === "works") {
    return { level: "protected", label: "Protected", connectable: false, detail: `Uses its own key, from ${where}.` };
  }
  if (a.key_status === "rejected") {
    return {
      level: "unprotected",
      label: "API key rejected — not protected",
      connectable: false,
      detail: `This agent sends the key from ${where}, and AgentGuards rejected it (revoked or deleted). Put a working key there, or remove it so the agent uses the saved key.`,
    };
  }
  return {
    level: "unverified",
    label: "Set up — couldn't verify its key",
    connectable: false,
    detail: `This agent sends the key from ${where}. AgentGuards couldn't be reached to check it; it is checked again on the next refresh.`,
  };
}

const KEY_PLACES: Record<string, string> = {
  claude_settings: "Claude Code's settings.json",
  claude_plugin: "the Claude Code plugin's settings",
  codex_token: "~/.codex/agentguards_token",
  env: "the AGENTGUARDS_API_KEY environment variable",
};

/** The saved key was rejected, by the installer's check or the extension's. */
export function savedKeyRejected(report: DoctorReport | undefined, saved: SavedKey): boolean {
  return (
    saved === "rejected" ||
    !!report?.agents.some((a) => a.key_source === "saved" && a.key_status === "rejected")
  );
}

/**
 * Carries the last key check over to a report made without one (key checks run at
 * most every few minutes): only for an agent whose key comes from the same place.
 */
export function withKeyStatus(report: DoctorReport, previous: DoctorReport | undefined): DoctorReport {
  if (!previous) return report;
  return {
    ...report,
    agents: report.agents.map((a) => {
      if (a.key_status || !a.key_found) return a;
      const p = previous.agents.find((x) => x.id === a.id && x.key_source === a.key_source && x.key_found);
      return p?.key_status ? { ...a, key_status: p.key_status } : a;
    }),
  };
}

/** Agents the installer would fix: what Connect sets up. */
export function connectable(report: DoctorReport, saved: SavedKey): DoctorAgent[] {
  return report.agents.filter((a) => effectiveState(report, a, saved).connectable);
}

/** Only these IDs are ever passed to `install --agents` (never free text). */
export const KNOWN_AGENT_IDS = new Set(["claude-code", "codex"]);
