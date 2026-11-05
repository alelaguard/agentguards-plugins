// AgentGuards API client. Runs in the extension host (Node 18+), uses global fetch.

import type { ExtensionRef } from "./inventory";

export type Verdict = "malicious" | "high" | "medium" | "clean" | "unknown" | "pending";

export interface Finding {
  kind: string;
  severity: string;
  title: string;
  detail?: string | null;
}

export interface ExtensionResult {
  id: string;
  version: string;
  source: string;
  target_platform?: string | null;
  verdict: Verdict;
  score: number;
  reason: string;
  findings: Finding[];
  retry_after_seconds?: number | null;
}

export interface ScanResponse {
  results: ExtensionResult[];
  /** The plan has no requests left: only malicious/high verdicts are answered. */
  quota_exhausted?: boolean;
}

export interface DeviceCode {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export type DeviceTokenResult = { api_key: string } | { error: string };

/** The plan's request quota is used up (HTTP 429 QUOTA_EXCEEDED). */
export class QuotaExceededError extends Error {}
/** The key is missing, wrong or revoked (HTTP 401/403). */
export class AuthError extends Error {}
/** Anything else: network, timeout, 5xx. Worth retrying later. */
export class ApiError extends Error {}

export const MAX_PER_REQUEST = 100;

/**
 * The API key only ever goes to AgentGuards over HTTPS: agentguards.co or a subdomain.
 * Plain http is allowed for a loopback address only (local development). Anything else
 * — a typo, or another extension rewriting the user setting — is refused rather than
 * sending the key there.
 */
export function checkedBaseUrl(raw: string): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new ApiError(`agentguards.apiUrl is not a valid URL: ${raw}`);
  }
  const host = u.hostname.toLowerCase();
  const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  const ours = host === "agentguards.co" || host.endsWith(".agentguards.co");
  if (!(loopback || (ours && u.protocol === "https:")) || u.username || u.password) {
    throw new ApiError(
      `agentguards.apiUrl must be an https://…agentguards.co address (got ${u.protocol}//${host})`,
    );
  }
  return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
}

export interface ClientOptions {
  baseUrl: string;
  clientHeader: string;
  getKey: () => Promise<string | undefined>;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export class AgentGuardsClient {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private readonly opts: ClientOptions) {
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  private async post(path: string, body: unknown, key?: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-AgentGuards-Client": this.opts.clientHeader,
    };
    if (key) headers["X-API-Key"] = key;
    try {
      const base = checkedBaseUrl(this.opts.baseUrl);
      return await this.fetchImpl(`${base}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
        // fetch keeps custom headers (X-API-Key) across redirects; never follow one.
        redirect: "error",
      });
    } catch (err) {
      if (err instanceof ApiError) throw err;
      const why = (err as Error)?.name === "AbortError" ? "timed out" : "could not be reached";
      throw new ApiError(`AgentGuards ${why}`);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Whether `key` is accepted, without using quota: a read-only dashboard endpoint
   * that screens nothing and records no usage. "unknown" on network trouble.
   */
  async keyStatus(key: string): Promise<"works" | "rejected" | "unknown"> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const base = checkedBaseUrl(this.opts.baseUrl);
      const res = await this.fetchImpl(`${base}/dashboard/checks`, {
        method: "GET",
        headers: { "X-API-Key": key, "X-AgentGuards-Client": this.opts.clientHeader },
        signal: controller.signal,
        redirect: "error",
      });
      if (res.status === 401 || res.status === 403) return "rejected";
      return res.ok ? "works" : "unknown";
    } catch {
      return "unknown";
    } finally {
      clearTimeout(timer);
    }
  }

  /** One batch (at most MAX_PER_REQUEST). Results come back in no guaranteed order. */
  async scan(refs: ExtensionRef[], editor: string): Promise<ScanResponse> {
    if (refs.length > MAX_PER_REQUEST) throw new Error("batch too large");
    const key = await this.opts.getKey();
    if (!key) throw new AuthError("Not signed in");
    const res = await this.post(
      "/v1/extensions/scan",
      { editor: editor.slice(0, 64), extensions: refs },
      key,
    );
    const body: any = await res.json().catch(() => ({}));
    if (res.status === 429 && body?.error === "QUOTA_EXCEEDED") {
      throw new QuotaExceededError(body.message || "Your plan's request quota is used up");
    }
    if (res.status === 401 || res.status === 403) {
      throw new AuthError(body?.message || body?.detail || "The API key was not accepted");
    }
    if (!res.ok || !Array.isArray(body?.results)) {
      throw new ApiError(`AgentGuards returned HTTP ${res.status}`);
    }
    return { results: body.results as ExtensionResult[], quota_exhausted: body.quota_exhausted === true };
  }

  async deviceCode(clientLabel: string): Promise<DeviceCode> {
    const res = await this.post("/v1/device/code", { client_label: clientLabel.slice(0, 200) });
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok || typeof body?.device_code !== "string") {
      throw new ApiError(`Could not start sign-in (HTTP ${res.status})`);
    }
    // The browser is sent to these addresses: only ever an AgentGuards page.
    for (const k of ["verification_uri", "verification_uri_complete"] as const) {
      if (!isOurPage(body[k])) throw new ApiError("Sign-in returned an unexpected address; not opening it");
    }
    return body as DeviceCode;
  }

  /** {api_key} once approved; otherwise the OAuth device-flow error code. */
  async deviceToken(deviceCode: string): Promise<DeviceTokenResult> {
    const res = await this.post("/v1/device/token", { device_code: deviceCode });
    const body: any = await res.json().catch(() => ({}));
    if (res.ok && typeof body?.api_key === "string") return { api_key: body.api_key };
    if (typeof body?.error === "string") return { error: body.error };
    throw new ApiError(`Sign-in check failed (HTTP ${res.status})`);
  }
}

/** An https://…agentguards.co page (or loopback, for development) — the same rule as the API. */
export function isOurPage(raw: unknown): boolean {
  if (typeof raw !== "string") return false;
  try {
    checkedBaseUrl(raw);
    return true;
  } catch {
    return false;
  }
}

/** Installer and dashboard keys look like ag_<...>. */
export function isAgentGuardsKey(k: unknown): k is string {
  return typeof k === "string" && k.startsWith("ag_") && k.length > "ag_".length + 8;
}
