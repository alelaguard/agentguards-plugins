// What gets sent to AgentGuards: extension ID, version, store and platform — never code.
// The server downloads the extension from the public store itself.

export type Source = "vscode-marketplace" | "open-vsx";
export type StoreSetting = "auto" | Source;

export interface InstalledExtension {
  id: string;
  version: string;
  displayName: string;
  /** From the install metadata; undefined for an extension installed without one. */
  targetPlatform?: string;
}

export interface ExtensionRef {
  id: string;
  version: string;
  source: Source;
  target_platform?: string;
}

// Mirrors the API's request validation (src/agentguards/extension_scan/schemas.py), so
// one odd entry can't 422 a whole batch.
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,127}\.[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VERSION_RE = /^\d{1,12}\.\d{1,12}\.\d{1,12}(?:[-+][0-9A-Za-z.-]{1,64})?$/;
const TARGET_RE = /^(?:universal|web|(?:win32|linux|alpine|darwin)-[a-z0-9]{2,8})$/;

/** Editors that install from the VS Code Marketplace; everything else uses Open VSX. */
const MARKETPLACE_APPS = new Set(["visual studio code", "visual studio code - insiders"]);

export function storeFor(appName: string, setting: StoreSetting | string | undefined): Source {
  if (setting === "vscode-marketplace" || setting === "open-vsx") return setting;
  return MARKETPLACE_APPS.has(appName.trim().toLowerCase()) ? "vscode-marketplace" : "open-vsx";
}

/** The marketplace platform name for this machine, e.g. "linux-x64". */
export function currentPlatform(platform: string, arch: string, musl = false): string | undefined {
  const a = arch === "arm" ? "armhf" : arch;
  if (platform === "win32" && ["x64", "arm64", "ia32"].includes(a)) return `win32-${a}`;
  if (platform === "darwin" && ["x64", "arm64"].includes(a)) return `darwin-${a}`;
  if (platform === "linux" && ["x64", "arm64", "armhf"].includes(a)) {
    return musl && a !== "armhf" ? `alpine-${a}` : `linux-${a}`;
  }
  return undefined;
}

/**
 * The build to check: the one installed when the install metadata says so, else this
 * machine's platform. The API checks that platform's build, or the universal one when
 * the extension has no platform builds — never another platform's.
 */
export function targetFor(installed: unknown, fallback: string | undefined): string | undefined {
  if (typeof installed === "string" && TARGET_RE.test(installed)) return installed;
  return fallback && TARGET_RE.test(fallback) ? fallback : undefined;
}

/** null when the ID or version can't be checked (e.g. a locally built "0.0.1-dev+x y"). */
export function toRef(
  ext: InstalledExtension,
  source: Source,
  fallbackTarget: string | undefined,
): ExtensionRef | null {
  if (!ID_RE.test(ext.id) || !VERSION_RE.test(ext.version)) return null;
  const ref: ExtensionRef = { id: ext.id, version: ext.version, source };
  const target = targetFor(ext.targetPlatform, fallbackTarget);
  if (target) ref.target_platform = target;
  return ref;
}

/** Results are stored per store + extension + version (case-insensitive IDs). */
export function refKey(ref: { id: string; version: string; source: string }): string {
  return `${ref.source}:${ref.id.toLowerCase()}@${ref.version}`;
}

/** A display name, skipping unresolved localisation placeholders like "%displayName%". */
export function displayName(raw: unknown, id: string): string {
  return typeof raw === "string" && raw.trim() && !/^%.*%$/.test(raw.trim()) ? raw.trim() : id;
}
