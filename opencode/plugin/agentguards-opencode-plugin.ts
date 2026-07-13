// AgentGuards guardrails plugin for OpenCode (opencode.ai).
//
// Unlike the Claude Code / Codex / Gemini hooks (subprocesses reading one JSON
// event from stdin per invocation), an OpenCode plugin is an in-process module
// that stays loaded for the life of the `opencode` process. There is no stdout
// JSON envelope protocol to speak: blocking a hook is `throw new Error(...)`,
// allowing is returning normally, and `permission.ask` is answered by setting
// `output.status` directly.
//
// Hooks implemented (confirmed against @opencode-ai/plugin 1.17.18's shipped
// dist/index.d.ts, not just the public docs page, which omits "chat.message"
// and "permission.ask" entirely):
//   - "chat.message"       -- the UserPromptSubmit equivalent: scans the user's
//                             prompt before the model sees it. Confirmed live
//                             (2026-07-13): throwing here halts the turn before
//                             the model is ever called.
//   - "tool.execute.before" -- authorizes `bash` calls before they run. A
//                             `require-approval`/`escalate`/`dry-run` verdict is
//                             a hard block with a "re-run to confirm" message
//                             (same as Gemini's fallback), not an interactive
//                             pause -- confirmed live that OpenCode's own
//                             permission system auto-rejects in headless runs
//                             without ever consulting a plugin hook, so relying
//                             on permission.ask alone would silently let
//                             borderline commands through.
//   - "permission.ask"      -- best-effort UX upgrade: if OpenCode's own
//                             permission system does end up asking about a call
//                             we already scored, answer it directly using that
//                             decision. Not the primary enforcement mechanism
//                             (see above).
//   - "tool.execute.after"  -- scans fetched web content (`webfetch`, or a
//                             `bash` call to curl/wget/etc.) and redacts it in
//                             place if flagged.
//
// Install:
//   Local:  copy this file to .opencode/plugin/agentguards.ts (project) or the
//           global plugin directory, or
//   npm:    `opencode plugin @agentguardsco/opencode-plugin`
//
// Environment variables:
//   AGENTGUARDS_API_KEY   Your ag_ API token (required)
//   AGENTGUARDS_URL       Base URL, only for a self-hosted instance
//                         (default: https://prod.agentguards.co)
//   AGENTGUARDS_FAIL_OPEN Set to "true" to allow instead of block when the
//                         AgentGuards API is unreachable (default: fail-closed)

import type { Plugin } from "@opencode-ai/plugin"

// Must default to prod: the API key is the only thing users are told to set (see
// the README/dashboard). Requiring AGENTGUARDS_URL too would fail-closed-block
// every message for anyone following the documented install. Same default as the
// Codex hook.
const AGENTGUARDS_URL = (process.env.AGENTGUARDS_URL || "https://prod.agentguards.co").replace(/\/+$/, "")
const AGENTGUARDS_API_KEY = process.env.AGENTGUARDS_API_KEY || ""

function failOpen(): boolean {
  return ["1", "true", "yes", "on"].includes((process.env.AGENTGUARDS_FAIL_OPEN || "").trim().toLowerCase())
}

function configured(): boolean {
  return Boolean(AGENTGUARDS_URL && AGENTGUARDS_API_KEY)
}

// OpenCode surfaces a thrown hook error to the user as an opaque "Unexpected
// server error" -- the real message only lands in the log. Print the panel to
// stderr (which does reach the user's terminal) before throwing, so a block
// shows its reason instead of looking like a crash.
function blockWith(message: string): never {
  console.error(message)
  throw new Error(message)
}

// A 429 QUOTA_EXCEEDED is a deliberate block with a user-facing message --
// surface it as such rather than as an opaque transport error.
class QuotaExceededError extends Error {
  userMessage: string
  constructor(message: string) {
    super(message)
    this.userMessage = message
  }
}

// A 403 is a deliberate access-control response (e.g. a feature the tenant
// hasn't enabled/purchased), not a transient outage -- callers must not
// fail-closed-block on this.
class ForbiddenError extends Error {}

async function post(path: string, payload: Record<string, unknown>, timeoutMs = 10_000): Promise<any> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(`${AGENTGUARDS_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": AGENTGUARDS_API_KEY },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
    if (res.status === 429) {
      const body = await res.json().catch(() => ({}) as any)
      if (body.error === "QUOTA_EXCEEDED") {
        throw new QuotaExceededError(body.message || "Monthly request quota reached.")
      }
    }
    if (res.status === 403) {
      const body = await res.json().catch(() => ({}) as any)
      throw new ForbiddenError(body.detail || "Forbidden")
    }
    if (!res.ok) {
      throw new Error(`AgentGuards API returned HTTP ${res.status}`)
    }
    return await res.json()
  } finally {
    clearTimeout(timer)
  }
}

const FETCH_BINARIES = new Set(["curl", "wget", "http", "https", "fetch", "aria2c"])

// Leading binary of each pipeline segment (skips leading VAR=val assignments).
function commandBinaries(command: string): string[] {
  const binaries: string[] = []
  for (const segment of (command || "").split(/\|\||&&|[|;&\n]/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean)
    let idx = 0
    while (idx < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[idx])) idx++
    if (idx < tokens.length) binaries.push(tokens[idx].split("/").pop() as string)
  }
  return binaries
}

function isFetchCommand(command: string): boolean {
  return commandBinaries(command).some((b) => FETCH_BINARIES.has(b))
}

type ActionDecision = "allow" | "deny" | "require-approval" | "dry-run" | "escalate"

// Per-session approved-binaries cache: a bash call that reached tool.execute.after
// actually ran (= approved), so we remember its binaries and skip re-asking later
// in the same session. The risk scorer always runs first, so a remembered binary
// can never carry a fresh destructive command through -- a deny still denies.
//
// Kept in-memory only (unlike the Python hooks' on-disk cache): each Python hook
// invocation is a fresh subprocess, but an OpenCode plugin instance already lives
// for the whole `opencode` process, so there's no cross-invocation state to bridge.
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000
const approvedBinaries = new Map<string, { binaries: Set<string>; ts: number }>()

// authorize_action decisions from tool.execute.before, keyed by callID, so a
// later permission.ask for the same call can reuse the verdict instead of
// re-scoring (and so require-approval can surface as a real "ask" rather than
// either a hard block or a silent allow).
const callDecisions = new Map<string, { decision: ActionDecision; reason: string; ts: number }>()

function pruneOld<K, V extends { ts: number }>(map: Map<K, V>): void {
  const now = Date.now()
  for (const [key, value] of map) {
    if (now - value.ts > SESSION_TTL_MS) map.delete(key)
  }
}

function rememberBinaries(sessionID: string, binaries: string[]): void {
  if (!sessionID || binaries.length === 0) return
  const entry = approvedBinaries.get(sessionID) ?? { binaries: new Set<string>(), ts: Date.now() }
  binaries.forEach((b) => entry.binaries.add(b))
  entry.ts = Date.now()
  approvedBinaries.set(sessionID, entry)
  pruneOld(approvedBinaries)
}

function hasApprovedBinaries(sessionID: string, binaries: string[]): boolean {
  if (!sessionID || binaries.length === 0) return false
  const entry = approvedBinaries.get(sessionID)
  if (!entry) return false
  return binaries.every((b) => entry.binaries.has(b))
}

function extractPromptText(parts: Array<{ type?: string; text?: string }>): string {
  return parts
    .filter((p) => p?.type === "text" && typeof p.text === "string")
    .map((p) => p.text as string)
    .join("\n")
}

const NOT_CONFIGURED_MESSAGE =
  "**[AgentGuards] Not configured**\nAGENTGUARDS_API_KEY must be set for the plugin to run.\nGet a key at https://agentguards.co/dashboard/keys, then:\n\n    export AGENTGUARDS_API_KEY=ag_your_token_here\n\nThe plugin is fail-closed, so it blocks until you set it."

export const AgentGuards: Plugin = async () => {
  return {
    "chat.message": async (_input, output) => {
      const text = extractPromptText((output.parts as any[]) || [])
      if (!text.trim()) return

      if (!configured()) {
        if (failOpen()) return
        blockWith(NOT_CONFIGURED_MESSAGE)
      }

      let result: any
      try {
        result = await post("/v1/guardrails/evaluate-input", { text, use_case: "opencode" })
      } catch (err) {
        if (err instanceof QuotaExceededError) {
          blockWith(`**[AgentGuards] Monthly quota reached**\n${err.userMessage}`)
        }
        if (failOpen()) return
        blockWith(
          `**[AgentGuards] Request blocked**\nAgentGuards is unreachable (${err}) and the plugin is fail-closed.\nSet AGENTGUARDS_FAIL_OPEN=true to allow prompts while the service is down.`,
        )
      }

      const decision = result.decision ?? "allow"
      if (decision === "block" || decision === "escalate") {
        const message =
          result.message ??
          "🛡️ [AgentGuards] Prompt blocked\nDecision: block\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
        const flagged = result.flagged_input
        blockWith(flagged ? `${message}\n\n    ${flagged}` : message)
      }
    },

    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = String((output.args as any)?.command ?? "")

      if (!configured()) {
        if (failOpen()) return
        blockWith(NOT_CONFIGURED_MESSAGE)
      }

      let result: any
      try {
        result = await post("/v1/actions/authorize", {
          action: "shell_command",
          tool: "bash",
          parameters: { command },
        })
      } catch (err) {
        if (err instanceof QuotaExceededError) {
          blockWith(`**[AgentGuards] Monthly quota reached**\n${err.userMessage}`)
        }
        if (failOpen()) return
        blockWith(
          `**[AgentGuards] Command blocked**\nAgentGuards is unreachable (${err}) and the plugin is fail-closed.\nSet AGENTGUARDS_FAIL_OPEN=true to allow commands while the service is down.`,
        )
      }

      const decision: ActionDecision = result.decision ?? "allow"
      const reason =
        result.reason ??
        "🛡️ [AgentGuards] Command blocked\nDecision: deny\nReason: policy - flagged by AgentGuards guardrails\nSeverity: high"
      callDecisions.set(input.callID, { decision, reason, ts: Date.now() })
      pruneOld(callDecisions)

      const shown = command.length > 500 ? `${command.slice(0, 500)}...` : command
      if (decision === "deny") {
        blockWith(`${reason}\n\n    ${shown}`)
      }
      if (decision === "allow") return

      // require-approval / dry-run / escalate: verified live (2026-07-13) that
      // OpenCode's own permission system does NOT reliably call permission.ask
      // before deciding -- in a headless `opencode run` session it auto-rejects
      // without ever consulting a plugin hook, and by default (no permission
      // rule configured for the tool) it doesn't ask at all, so silently
      // returning here would let a borderline command through unchecked. Hard
      // block instead, same as Gemini's proven fallback, unless every binary in
      // this command was already approved earlier in the session.
      const binaries = commandBinaries(command)
      if (binaries.length > 0 && hasApprovedBinaries(input.sessionID, binaries)) return
      blockWith(
        `${reason}\n\n    ${shown}\n\nRe-run after confirming you want to proceed with this command.`,
      )
    },

    // Best-effort UX upgrade: if OpenCode's own permission system does end up
    // asking for a call we already scored (confirmed to happen in some paths,
    // just not reliably in headless runs -- see the note in tool.execute.before
    // above), answer it directly instead of leaving OpenCode's own prompt up,
    // using the decision we cached by callID.
    "permission.ask": async (input, output) => {
      const cached = input.callID ? callDecisions.get(input.callID) : undefined
      let decision: ActionDecision | undefined = cached?.decision

      // Fall back to scoring directly if this permission ask didn't come through
      // our tool.execute.before path (e.g. ordering differs from what we assume,
      // or OpenCode's own permission system asked independently).
      if (!decision && input.type === "bash" && typeof input.pattern === "string" && configured()) {
        try {
          const result = await post("/v1/actions/authorize", {
            action: "shell_command",
            tool: "bash",
            parameters: { command: input.pattern },
          })
          decision = result.decision ?? "allow"
        } catch {
          // Leave output.status untouched below -- fall through to OpenCode's
          // default permission behavior rather than guessing on a failed lookup.
        }
      }

      if (decision === "deny") {
        output.status = "deny"
      } else if (decision === "allow") {
        output.status = "allow"
      } else if (decision === "require-approval" || decision === "escalate" || decision === "dry-run") {
        output.status = "ask"
      }
      // Anything else (e.g. non-bash permission types we don't score, like write
      // or edit) is left untouched so OpenCode's default flow applies.
    },

    "tool.execute.after": async (input, output) => {
      const sessionID = input.sessionID

      if (input.tool === "bash") {
        const command = String((input.args as any)?.command ?? "")
        // The command already ran (= it was allowed/approved) -- remember its
        // binaries for this session so we don't re-ask for them.
        rememberBinaries(sessionID, commandBinaries(command))
        if (!isFetchCommand(command)) return
      } else if (input.tool !== "webfetch") {
        return
      }

      // curl/wget etc. fetch web content the same way the webfetch tool does --
      // scan it here too, deterministically. This does NOT rely on the model
      // cooperatively calling the MCP check_input tool.
      const text = output.output || ""
      if (!text.trim()) return

      if (!configured()) {
        if (failOpen()) return
        output.output = "[AgentGuards: web content withheld -- plugin not configured]"
        return
      }

      let result: any
      try {
        result = await post("/v1/guardrails/evaluate-input", { text, use_case: "opencode", channel: "opencode" })
      } catch (err) {
        if (err instanceof QuotaExceededError) {
          output.output = "[AgentGuards: web content withheld -- monthly request quota reached]"
          return
        }
        if (failOpen()) return
        output.output = "[AgentGuards: web content withheld -- service unreachable]"
        return
      }

      const decision = result.decision ?? "allow"
      if (decision !== "allow") {
        output.output = "[AgentGuards: web content withheld -- flagged by guardrails]"
      }
    },
  }
}
