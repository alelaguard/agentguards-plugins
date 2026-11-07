// Extensions installed on disk, including ones VS Code hasn't started yet.
//
// vscode.extensions.all lists only the extensions running in this window. One that VS
// Code installed but won't start until a restart, or that is disabled, isn't there,
// so it would only be checked once its code was already running. The editor keeps the
// full list in <extensions dir>/extensions.json; folders in .obsolete are being removed.
import * as fs from "node:fs";
import * as path from "node:path";
import { displayName, type InstalledExtension } from "./inventory";

const MAX_ENTRIES = 5_000;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

export interface OnDiskExtension extends InstalledExtension {
  /** The extension's folder name inside the extensions directory. */
  folder: string;
}

function readJson(file: string, maxBytes: number): unknown {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > maxBytes) return undefined;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return undefined;
  }
}

/** Folder names VS Code has marked for removal (uninstalled, or replaced by an update). */
export function obsoleteFolders(extensionsDir: string): Set<string> {
  const raw = readJson(path.join(extensionsDir, ".obsolete"), MAX_FILE_BYTES);
  const out = new Set<string>();
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [k, v] of Object.entries(raw)) if (v === true) out.add(k.toLowerCase());
  }
  return out;
}

/**
 * Every extension `extensions.json` lists, minus those being removed. Returns [] when
 * the directory has no extensions.json (e.g. running from a development folder). The
 * display name comes from the extension's own package.json when it can be read.
 */
export function readOnDisk(extensionsDir: string): OnDiskExtension[] {
  const list = readJson(path.join(extensionsDir, "extensions.json"), MAX_FILE_BYTES);
  if (!Array.isArray(list)) return [];
  const obsolete = obsoleteFolders(extensionsDir);
  const out: OnDiskExtension[] = [];
  for (const entry of list.slice(0, MAX_ENTRIES)) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    const ident = e.identifier as Record<string, unknown> | undefined;
    const id = typeof ident?.id === "string" ? ident.id : undefined;
    const version = typeof e.version === "string" ? e.version : undefined;
    const folder = typeof e.relativeLocation === "string" ? e.relativeLocation : undefined;
    // A folder name only: never follow a path out of the extensions directory.
    if (!id || !version || !folder || folder !== path.basename(folder) || folder.startsWith(".")) continue;
    if (obsolete.has(folder.toLowerCase())) continue;
    const meta = (e.metadata ?? {}) as Record<string, unknown>;
    const pj = readJson(path.join(extensionsDir, folder, "package.json"), MAX_MANIFEST_BYTES) as
      | Record<string, unknown>
      | undefined;
    if (!pj) continue; // listed but not (or no longer) on disk
    out.push({
      id,
      version,
      displayName: displayName(pj.displayName, id),
      targetPlatform: typeof meta.targetPlatform === "string" ? meta.targetPlatform : undefined,
      folder,
    });
  }
  return out;
}

/**
 * The running extensions plus those only on disk. Keyed by ID and version, so an update
 * waiting for a restart is checked alongside the version still running.
 */
export function mergeInstalled<T extends InstalledExtension>(
  running: T[],
  onDisk: InstalledExtension[],
  skipId: string,
): { ext: InstalledExtension; running: boolean }[] {
  const key = (e: InstalledExtension) => `${e.id.toLowerCase()}@${e.version}`;
  const seen = new Set(running.map(key));
  const out: { ext: InstalledExtension; running: boolean }[] = running.map((ext) => ({ ext, running: true }));
  for (const ext of onDisk) {
    if (ext.id.toLowerCase() === skipId || seen.has(key(ext))) continue;
    seen.add(key(ext));
    out.push({ ext: { id: ext.id, version: ext.version, displayName: ext.displayName, targetPlatform: ext.targetPlatform }, running: false });
  }
  return out;
}
