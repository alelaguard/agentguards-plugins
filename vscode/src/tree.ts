import * as vscode from "vscode";
import type { StoredResult } from "./core/scanner";
import { SEVERITY_ORDER } from "./core/scanner";

export interface Row {
  key: string;
  id: string;
  name: string;
  version: string;
  result?: StoredResult;
  ignored: boolean;
  /** Not sent: the ID or version isn't one the store could have published. */
  uncheckable?: boolean;
}

type Node =
  | { kind: "ext"; row: Row }
  | { kind: "detail"; parent: Row; index: number; label: string; icon: string; tip?: string };

const VERDICT_LABEL: Record<string, string> = {
  malicious: "Malicious",
  high: "High risk",
  medium: "Medium risk",
  clean: "Clean",
  unknown: "Not checked",
  pending: "Checking…",
};

function verdictIcon(row: Row): vscode.ThemeIcon {
  const v = row.result?.verdict;
  if (row.uncheckable || !v) return new vscode.ThemeIcon("circle-outline");
  if (v === "malicious") return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
  if (v === "high") return new vscode.ThemeIcon("warning", new vscode.ThemeColor("errorForeground"));
  if (v === "medium")
    return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
  if (v === "clean") return new vscode.ThemeIcon("pass", new vscode.ThemeColor("testing.iconPassed"));
  if (v === "pending") return new vscode.ThemeIcon("sync~spin");
  return new vscode.ThemeIcon("question");
}

export function isFlagged(v: string | undefined): boolean {
  return v === "malicious" || v === "high" || v === "medium";
}

export class ExtensionsTree implements vscode.TreeDataProvider<Node> {
  private readonly emitter = new vscode.EventEmitter<Node | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;
  private rows: Row[] = [];
  private nodes = new Map<string, Node>();

  setRows(rows: Row[]): void {
    this.rows = [...rows].sort((a, b) => {
      const sa = a.ignored ? 6 : (SEVERITY_ORDER[a.result?.verdict ?? "unknown"] ?? 6);
      const sb = b.ignored ? 6 : (SEVERITY_ORDER[b.result?.verdict ?? "unknown"] ?? 6);
      return sa - sb || a.name.localeCompare(b.name);
    });
    this.nodes = new Map(this.rows.map((row) => [row.key, { kind: "ext", row } as Node]));
    this.emitter.fire(undefined);
  }

  get isEmpty(): boolean {
    return this.rows.length === 0;
  }

  nodeFor(key: string): Node | undefined {
    return this.nodes.get(key);
  }

  getParent(node: Node): Node | undefined {
    return node.kind === "detail" ? this.nodes.get(node.parent.key) : undefined;
  }

  getChildren(node?: Node): Node[] {
    if (!node) return this.rows.map((r) => this.nodes.get(r.key)!);
    if (node.kind !== "ext") return [];
    const row = node.row;
    const r = row.result;
    const out: Node[] = [];
    const detail = (label: string, icon: string, tip?: string): Node => ({
      kind: "detail",
      parent: row,
      // Position, not label: two findings can have the same text (e.g. one CVE in two
      // nested copies of a package), and VS Code rejects duplicate tree item IDs.
      index: out.length,
      label,
      icon,
      tip,
    });
    if (row.uncheckable) {
      out.push(detail("Not a store release (local or development build) — not checked", "info"));
      return out;
    }
    if (!r) {
      out.push(detail("Not checked yet", "info"));
      return out;
    }
    out.push(detail(r.reason, "info", r.reason));
    for (const f of r.findings ?? []) {
      out.push(
        detail(`[${f.severity}] ${f.title}`, f.severity === "critical" || f.severity === "high" ? "warning" : "circle-small", f.detail ?? undefined),
      );
    }
    if (row.ignored) out.push(detail("You chose to ignore this warning", "eye-closed"));
    out.push(detail(`Checked ${new Date(r.checkedAt).toLocaleString()}`, "history"));
    return out;
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === "detail") {
      const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon(node.icon);
      item.tooltip = node.tip;
      item.id = `${node.parent.key}#${node.index}`;
      return item;
    }
    const row = node.row;
    const v = row.result?.verdict;
    const item = new vscode.TreeItem(
      row.name,
      isFlagged(v) ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.Collapsed,
    );
    item.id = row.key;
    item.iconPath = verdictIcon(row);
    item.description = `${row.version} · ${row.uncheckable ? "Not checked" : VERDICT_LABEL[v ?? ""] ?? "Not checked yet"}${row.ignored ? " (ignored)" : ""}`;
    item.tooltip = new vscode.MarkdownString(
      `**${row.name}** \`${row.id}@${row.version}\`\n\n${row.result?.reason ?? "Not checked yet"}`,
    );
    item.contextValue = ["ext", isFlagged(v) ? "flagged" : "", row.ignored ? "ignored" : ""]
      .filter(Boolean)
      .join(" ");
    return item;
  }
}
