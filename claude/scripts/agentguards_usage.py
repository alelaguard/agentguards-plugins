"""LLM usage reports for the AgentGuards dashboard — opt-in, counts only.

Reads Claude Code's own session transcript (``transcript_path``, plus the session's
``subagents/*.jsonl``) a piece at a time and sends what was used since the last report:
tokens per model, tool calls, sub-agents started, and loop counters. Never prompts,
commands, file paths, tool inputs or outputs — tool calls and results are reduced to
local hashes that are compared here and never sent.

Off unless the tenant turned "Track LLM usage" on in the dashboard. The answer is
cached per API key and URL (_CONFIG_PATH); while it is "off", run-hook.sh does not even
start Python for the per-tool event (no _MARKER) and asks again at a turn end at most
once an hour.

Everything here fails silent: a usage report must never block, slow down or change
what the guardrail hooks decide. Python 3.8+ (macOS system Python).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

_DIR = os.path.expanduser("~/.claude")
_STATE_PATH = os.path.join(_DIR, "agentguards_usage_state.json")
_CONFIG_PATH = os.path.join(_DIR, "agentguards_usage_config.json")
# Message ids already reported, one per line: Claude Code copies earlier messages, ids
# and all, into the transcript of a resumed or forked session.
_IDS_PATH = os.path.join(_DIR, "agentguards_usage_ids.txt")
# Exists only while tracking is on for some key; run-hook.sh checks it before starting
# Python for the per-tool event.
_MARKER = os.path.join(_DIR, "agentguards_usage_on")
_LOCK_PATH = os.path.join(_DIR, "agentguards_usage.lock")
_VERSION = 2

_TTL_ON = 600  # seconds before asking again whether tracking is on, while it is
_TTL_OFF = 3600  # … and while it is off (run-hook.sh uses the same hour)
_DEFAULT_INTERVAL = 60  # least seconds between reports during a turn (server may raise)
_RETRY_AFTER = 300  # after a 429
_RETRY_FAILED = 60  # after any other failure
_MAX_RETRIES = 3  # the same report, before it is dropped
_TIMEOUT = 3
_SESSION_TTL = 7 * 24 * 3600  # idle sessions then keep only their read positions
_SESSION_FORGET = 90 * 24 * 3600
_MAX_READ = 32 * 1024 * 1024  # bytes per file per report; the rest goes next time
_MAX_IDS = 50_000  # reported message ids kept (about 26 bytes each on disk)
_MAX_PENDING = 200  # tool calls waiting for their result, per file
_MAX_MODELS = 20
_MODEL_RE = re.compile(r"[^A-Za-z0-9._:@/\[\]-]")
_SPAWN_TOOLS = ("Task", "Agent")


def _now() -> float:
    return time.time()


def _owner(url: str, key: str) -> str:
    return hashlib.sha256(f"{url}|{key}".encode()).hexdigest()[:16]


def _h(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


def _read_json(path: str) -> dict:
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_json(path: str, data: dict) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


class _Api:
    """GET/POST to the telemetry endpoints. Deliberately not the hook's _post: that one
    maps quota/403 answers onto guardrail decisions, which a usage report must never
    trigger, and waits far longer than a report may."""

    def __init__(self, url: str, key: str, client: str, ssl_context):
        self.url, self.key, self.client, self.ssl_context = url, key, client, ssl_context

    def call(self, path: str, payload=None) -> dict:
        req = urllib.request.Request(
            f"{self.url}{path}",
            data=None if payload is None else json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.key,
                "X-AgentGuards-Client": self.client,
            },
            method="GET" if payload is None else "POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT, context=self.ssl_context()) as r:
            body = json.loads(r.read())
        return body if isinstance(body, dict) else {}


# --- config (per API key + URL) -------------------------------------------------------

def _configs() -> dict:
    c = _read_json(_CONFIG_PATH)
    owners = c.get("owners") if c.get("v") == _VERSION else None
    return owners if isinstance(owners, dict) else {}


def _save_config(owner: str, enabled: bool, interval: int) -> None:
    owners = _configs()
    owners[owner] = {"at": _now(), "enabled": enabled, "interval": interval}
    # Forget keys not seen for a week, so an old key cannot hold the marker on.
    owners = {k: v for k, v in owners.items() if _now() - float(v.get("at", 0)) < _SESSION_TTL}
    _write_json(_CONFIG_PATH, {"v": _VERSION, "owners": owners})
    try:
        if any(v.get("enabled") for v in owners.values()):
            with open(_MARKER, "w") as fh:
                fh.write("1\n")
        elif os.path.exists(_MARKER):
            os.unlink(_MARKER)
    except OSError:
        pass


def _config(api: _Api, owner: str, *, may_ask: bool) -> dict:
    """{"enabled": bool, "interval": int} for this key, asking the server when due."""
    cached = _configs().get(owner)
    if cached is not None:
        ttl = _TTL_ON if cached.get("enabled") else _TTL_OFF
        if not may_ask or _now() - float(cached.get("at", 0)) < ttl:
            return cached
    elif not may_ask:
        return {"enabled": False}
    try:
        answer = api.call("/v1/telemetry/config")
        enabled = bool(answer.get("enabled"))
        interval = answer.get("interval")
        interval = max(30, int(interval)) if isinstance(interval, int) else _DEFAULT_INTERVAL
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404, 405):
            # No such endpoint (an older server) or a rejected key: off.
            enabled, interval = False, _DEFAULT_INTERVAL
        else:
            return _keep(owner, cached)
    except Exception:
        return _keep(owner, cached)
    _save_config(owner, enabled, interval)
    return {"enabled": enabled, "interval": interval}


def _keep(owner: str, cached: dict | None) -> dict:
    """The server could not answer: keep the last answer, ask again after the TTL."""
    enabled = bool(cached and cached.get("enabled"))
    interval = int((cached or {}).get("interval") or _DEFAULT_INTERVAL)
    _save_config(owner, enabled, interval)
    return {"enabled": enabled, "interval": interval}


# --- reported message ids (machine-wide) ----------------------------------------------

def _reported_ids() -> dict:
    """{hashed message id: tag of the session that reported it}."""
    out = {}
    try:
        with open(_IDS_PATH) as fh:
            for line in fh:
                parts = line.split()
                if parts:
                    # A line without a tag (pre-release builds) counts as another
                    # session's, so it is never reported again.
                    out[parts[0]] = parts[1] if len(parts) > 1 else "?"
    except OSError:
        pass
    return out


def _remember_ids(new: list, tag: str, known: dict) -> None:
    if not new:
        return
    lines_new = [f"{hid} {tag}" for hid in new]
    try:
        os.makedirs(_DIR, exist_ok=True)
        if len(known) + len(new) > _MAX_IDS:
            with open(_IDS_PATH) as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            keep = (lines + lines_new)[-(_MAX_IDS * 4 // 5):]
            tmp = f"{_IDS_PATH}.{os.getpid()}.tmp"
            with open(tmp, "w") as fh:
                fh.write("\n".join(keep) + "\n")
            os.replace(tmp, _IDS_PATH)
        else:
            with open(_IDS_PATH, "a") as fh:
                fh.write("\n".join(lines_new) + "\n")
    except OSError:
        pass


# --- transcript reading ---------------------------------------------------------------

def _new_loop() -> dict:
    return {"prev": None, "run_o": 0, "run_e": 0, "acts": [], "pp": 0}


def _is_prompt(rec: dict, content) -> bool:
    if rec.get("isMeta") or rec.get("isSidechain"):
        return False
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list):
        blocks = [b for b in content if isinstance(b, dict)]
        return any(b.get("type") == "text" for b in blocks) and not any(
            b.get("type") == "tool_result" for b in blocks
        )
    return False


def _step(loop: dict, action: str, result: str, is_error: bool, out: dict) -> None:
    """One tool call and its result through the OpenHands-style loop counters."""
    prev = loop["prev"]
    same = prev is not None and prev[0] == action
    loop["run_o"] = loop["run_o"] + 1 if same and prev[1] == result else 1
    loop["run_e"] = (loop["run_e"] + 1 if same and prev[2] and is_error
                     else (1 if is_error else 0))
    acts = (loop["acts"] + [[action, result]])[-3:]
    if len(acts) == 3 and acts[2] == acts[0] and acts[2] != acts[1]:
        loop["pp"] += 1
    else:
        loop["pp"] = 0
    loop["acts"], loop["prev"] = acts, [action, result, is_error]
    out["same_result"] = max(out["same_result"], loop["run_o"])
    out["same_error"] = max(out["same_error"], loop["run_e"])
    out["ping_pong"] = max(out["ping_pong"], loop["pp"] // 2)


def _chunk(path: str, fstate: dict) -> bytes:
    """The complete lines appended since the last report (moves the offset past them)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return b""
    off = int(fstate.get("off", 0))
    if size < off:
        # Rewritten under us: its earlier lines were reported (or can't be told apart from
        # ones that were), so carry on from its new end rather than count them again.
        fstate["off"], fstate["skip"] = size, False
        return b""
    if size == off:
        return b""
    with open(path, "rb") as fh:
        fh.seek(off)
        chunk = fh.read(_MAX_READ)
    if fstate.get("skip"):
        # Inside a line longer than _MAX_READ: drop through its end, then carry on.
        nl = chunk.find(b"\n")
        if nl < 0:
            fstate["off"] = off + len(chunk)
            return b""
        off, chunk, fstate["skip"] = off + nl + 1, chunk[nl + 1:], False
    end = chunk.rfind(b"\n")
    if end < 0:
        if len(chunk) >= _MAX_READ:  # one line bigger than a whole read: skip it
            fstate["off"], fstate["skip"] = off + len(chunk), True
        else:
            fstate["off"] = off  # no complete line yet
        return b""
    fstate["off"] = off + end + 1
    return chunk[: end + 1]


def _read_file(path: str, fstate: dict, sess: dict, acc: dict, main: bool) -> None:
    """Fold what was appended to *path* since the last report into *acc*."""
    chunk = _chunk(path, fstate)
    if not chunk:
        return
    loop = fstate.setdefault("loop", _new_loop())
    pending = fstate.setdefault("pending", {})
    for line in chunk.splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        content = msg.get("content")
        mid = msg.get("id") if isinstance(msg.get("id"), str) else None
        hid = _h(mid) if mid else None
        reported_by = acc["old_ids"].get(hid) if hid else None
        if rec.get("type") == "assistant" and reported_by not in (None, acc["tag"]):
            continue  # copied from another session (resume / fork): already reported
        if rec.get("type") == "user":
            if main and _is_prompt(rec, content):
                sess["since_prompt"] = 0
                fstate["loop"] = loop = _new_loop()
                pending.clear()
            for b in content if isinstance(content, list) else []:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    action = pending.pop(str(b.get("tool_use_id")), None)
                    if action is not None:
                        _step(loop, action, _h(b.get("content")), bool(b.get("is_error")),
                              acc["loop"])
            continue
        if rec.get("type") != "assistant":
            continue
        # The report's window comes only from the work it counts, so copied history
        # (and its old timestamps) cannot stretch it.
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            acc["start"] = ts if acc["start"] is None else min(acc["start"], ts)
            acc["end"] = ts if acc["end"] is None else max(acc["end"], ts)
        for b in content if isinstance(content, list) else []:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                acc["tool_calls"] += 1
                sess["since_prompt"] = int(sess.get("since_prompt", 0)) + 1
                if b.get("name") in _SPAWN_TOOLS:
                    acc["subagents"] += 1
                if len(pending) < _MAX_PENDING:
                    pending[str(b.get("id"))] = _h([b.get("name"), b.get("input")])
        usage, model = msg.get("usage"), msg.get("model")
        # Claude Code repeats a message's usage on each of its content blocks: counted
        # once, whether the repeats land in this report or a later one.
        if not isinstance(usage, dict) or not hid or not isinstance(model, str):
            continue
        if reported_by is not None or hid in acc["new_set"]:
            continue
        acc["new_set"].add(hid)
        acc["new_ids"].append(hid)
        if model.startswith("<"):  # "<synthetic>": Claude Code's own, no real tokens
            continue
        name = _MODEL_RE.sub("", model)[:100] or "unknown"
        m = acc["models"].setdefault(
            name, {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0, "messages": 0}
        )
        for field, src in (("input", "input_tokens"), ("output", "output_tokens"),
                           ("cache_read", "cache_read_input_tokens"),
                           ("cache_write", "cache_creation_input_tokens")):
            v = usage.get(src)
            if isinstance(v, int) and v > 0:
                m[field] += v
        m["messages"] += 1


def _transcripts(event: dict) -> list:
    """(path, is_main) for the session transcript and its sub-agents' transcripts."""
    main = event.get("transcript_path")
    if not isinstance(main, str) or not main.endswith(".jsonl"):
        return []
    out = [(main, True)]
    sid = event.get("session_id")
    subdir = os.path.join(os.path.dirname(main), str(sid), "subagents") if sid else ""
    try:
        names = sorted(os.listdir(subdir)) if subdir else []
    except OSError:
        names = []
    out += [(os.path.join(subdir, n), False) for n in names if n.endswith(".jsonl")]
    return out


# --- reporting ------------------------------------------------------------------------

def _utc(ts: str | None) -> str:
    return ts or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _report(event: dict, sess: dict, old_ids: dict, tag: str) -> tuple:
    """Read what is new into *sess* (offsets move past it): (report or None, the new
    message ids it covers)."""
    acc = {
        "start": None, "end": None, "models": {}, "tool_calls": 0, "subagents": 0,
        "loop": {"same_result": 0, "same_error": 0, "ping_pong": 0},
        "old_ids": old_ids, "tag": tag, "new_ids": [], "new_set": set(),
    }
    fresh = "files" not in sess
    files = sess.setdefault("files", {})
    lost = fresh and tag in set(old_ids.values())
    span = []
    for path, main in _transcripts(event):
        fstate = files.get(path)
        if fstate is None:
            fstate = files[path] = {}
            if lost:
                # This session reported before but its state is gone (lost file): carry
                # on from where the transcript ends now rather than count it again.
                try:
                    fstate["off"] = os.path.getsize(path)
                except OSError:
                    pass
        before = int(fstate.get("off", 0))
        _read_file(path, fstate, sess, acc, main)
        after = int(fstate.get("off", 0))
        if after > before:
            span.append([os.path.basename(path), before, after])
    models = [
        {"model": k, **v} for k, v in acc["models"].items()
        if v["input"] or v["output"] or v["cache_read"] or v["cache_write"]
    ][:_MAX_MODELS]
    if not models and not acc["tool_calls"]:
        return None, acc["new_ids"]
    session = hashlib.sha256(str(event.get("session_id")).encode()).hexdigest()[:32]
    start, end = _utc(acc["start"]), _utc(acc["end"])
    return {
        "session": session,
        # Names exactly these transcript lines; a resend of this report (saved as it
        # was) carries the same id, so the server stores it once.
        "report_id": hashlib.sha256(json.dumps([session, sorted(span)]).encode()).hexdigest()[:32],
        "start": start,
        "end": max(start, end),
        "models": models,
        "tool_calls": acc["tool_calls"],
        "subagents": acc["subagents"],
        "calls_since_prompt": int(sess.get("since_prompt", 0)),
        "loop": acc["loop"],
    }, acc["new_ids"]


def _lock():
    """A non-blocking lock so parallel hooks never read the same lines twice."""
    try:
        import fcntl
    except ImportError:  # Windows: this module does not run there yet
        return None
    try:
        os.makedirs(_DIR, exist_ok=True)
        fh = open(_LOCK_PATH, "w")
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        return None


def _tidy(sessions: dict, keep: str, now: float) -> None:
    """Sessions idle a week keep only their read positions (so a session resumed later
    never recounts its history); after _SESSION_FORGET they go entirely."""
    for s in list(sessions):
        if s == keep:
            continue
        idle = now - float(sessions[s].get("at", 0))
        if idle > _SESSION_FORGET:
            del sessions[s]
        elif idle > _SESSION_TTL and set(sessions[s]) - {"at", "files", "unsent"}:
            v = sessions[s]
            sessions[s] = {
                "at": v.get("at", 0),
                "files": {p: {"off": f.get("off", 0)} for p, f in (v.get("files") or {}).items()},
            }
            if v.get("unsent"):  # resent if the session is ever picked up again
                sessions[s]["unsent"] = v["unsent"]


def handle(event_type: str, event: dict, *, url: str, key: str, client: str,
           ssl_context) -> str | None:
    """Report this session's usage if due. At "Stop", returns a notice to show the user."""
    if not key or not isinstance(event, dict) or not event.get("session_id"):
        return None
    api, owner = _Api(url, key, client, ssl_context), _owner(url, key)
    at_turn_end = event_type in ("Stop", "SubagentStop")
    config = _config(api, owner, may_ask=at_turn_end)
    if not config.get("enabled"):
        return None
    lock = _lock()
    if lock is None:
        return None
    try:
        state = _read_json(_STATE_PATH)
        if state.get("v") != _VERSION or not isinstance(state.get("sessions"), dict):
            state = {"v": _VERSION, "sessions": {}}
        sessions = state["sessions"]
        now = _now()
        sid = _h([owner, event.get("session_id")])
        sess = sessions.setdefault(sid, {})
        unsent = sess.get("unsent")
        if unsent:
            due = now >= float(unsent.get("retry_at", 0))
        else:
            interval = int(config.get("interval") or _DEFAULT_INTERVAL)
            # The turn's last reply goes now, or it may never go.
            due = event_type == "Stop" or now - float(sess.get("sent", 0)) >= interval
        if due:
            _tidy(sessions, sid, now)
            sess["at"] = now
            _send(api, event, sess, owner, sid[:8], now, turn_end=event_type == "Stop",
                  save=lambda: _write_json(_STATE_PATH, state))
        notice = sess.pop("pending_notice", None) if event_type == "Stop" else None
        if due or notice:
            _write_json(_STATE_PATH, state)
        return notice
    finally:
        lock.close()


def _switch_off(owner: str) -> None:
    cached = _configs().get(owner) or {}
    _save_config(owner, False, int(cached.get("interval") or _DEFAULT_INTERVAL))


def _send(api: _Api, event: dict, sess: dict, owner: str, tag: str, now: float, *,
          turn_end: bool, save) -> None:
    """Resend a report that failed earlier, exactly as it was; else read and send what is
    new. A report that can't be sent is kept whole in ``unsent`` and resent up to
    _MAX_RETRIES times, then dropped.

    Write-ahead: before every POST the state is saved as if it will fail (lines marked
    read, the report in ``unsent`` with this try counted and its next retry time). Claude
    Code kills a hook that runs too long or that the user interrupts; whenever that
    happens, the next event finds the report still waiting, with its tries counted —
    nothing lost, nothing retried without limit, nothing read twice."""
    unsent = sess.get("unsent")
    if unsent and int(unsent.get("tries", 1)) >= _MAX_RETRIES:
        del sess["unsent"]  # dropped: one bad report must not stall the session
        unsent = None
    if unsent:
        tries = int(unsent.get("tries", 1)) + 1
        unsent["tries"], unsent["retry_at"] = tries, now + _RETRY_FAILED
        save()
        outcome = _post(api, sess, owner, unsent["report"], now)
        if outcome == "throttled":
            unsent["retry_at"] = now + _RETRY_AFTER
        if outcome in ("failed", "throttled"):
            if tries >= _MAX_RETRIES:
                del sess["unsent"]
            return
        if outcome == "off":
            # Kept for when tracking is back on; an "off" answer doesn't use up a try.
            unsent["tries"], unsent["retry_at"] = tries - 1, 0
            return
        del sess["unsent"]
        if not turn_end:
            return  # one report per tool call; the turn's own lines go at its end
    old_ids = _reported_ids()
    report, new_ids = _report(event, sess, old_ids, tag)
    if report is None:
        _remember_ids(new_ids, tag, old_ids)  # (synthetic-only messages: nothing to lose)
        return
    sess["unsent"] = {"report": report, "tries": 1, "retry_at": now + _RETRY_FAILED}
    save()  # before the ids: a kill in between must leave the report saved, not skipped
    _remember_ids(new_ids, tag, old_ids)
    outcome = _post(api, sess, owner, report, now)
    if outcome in ("sent", "dropped"):
        del sess["unsent"]
    elif outcome == "throttled":
        sess["unsent"]["retry_at"] = now + _RETRY_AFTER
    elif outcome == "off":
        sess["unsent"]["retry_at"] = 0


def _post(api: _Api, sess: dict, owner: str, report: dict, now: float) -> str:
    """POST one report: "sent", "dropped" (refused for good), "off" (tracking is off for
    this key now), "throttled" (429) or "failed" (worth another try)."""
    try:
        answer = api.call("/v1/telemetry/agent-usage", report)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404, 405):
            _switch_off(owner)  # key rejected, or no such endpoint here
            return "off"
        if exc.code == 429:
            return "throttled"
        if exc.code == 408 or exc.code >= 500:
            return "failed"
        return "dropped"
    except Exception:  # unreachable or timed out
        return "failed"
    sess["sent"] = now
    notice = answer.get("notice")
    if isinstance(notice, str) and notice.strip():
        shown = sess.setdefault("notices", [])
        nh = _h(notice)
        if nh not in shown:
            shown.append(nh)
            sess["pending_notice"] = notice.strip()[:500]
    if answer.get("enabled") is False:
        _switch_off(owner)
    return "sent"
