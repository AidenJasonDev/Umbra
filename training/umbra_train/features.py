"""Feature extraction. Column names and IDs match training/FEATURES.md.

Timing features (`tim_*`) come from timing.py.
compute(fs, net, ctx, t0, t1) works on any time slice, so the same code
produces per-session rows and sliding-window rows (for the live score).
"""

from __future__ import annotations

import base64
import math
import os
import re
import statistics
from bisect import bisect_left, bisect_right
from pathlib import Path

from .config import LLM_HOST_SUFFIXES
from . import timing
from .lab import in_scope

SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}
EDITORS = {"vim", "vi", "nvim", "nano", "emacs", "micro", "pico", "code", "hx",
           "notepad", "notepad++", "wordpad"}
RE_OUTPUT_LIMIT = re.compile(r"\|\s*(head|tail)\b|2>&1|\bsed -n\b|\bwc -l\b"
                             r"|Select-Object\s+-(First|Last)|\|\s*select\s+-(first|last)", re.I)
RE_NONINTERACTIVE = re.compile(
    r"(^|\s)(-y|--yes|--no-pager|-q|--quiet|--non-interactive|--no-input|-f)(\s|$)"
    r"|GIT_PAGER=|PAGER=cat|DEBIAN_FRONTEND|--batch"
    r"|-NonInteractive|-Force\b|-Confirm:\$false|/quiet\b|/y\b", re.I)
RE_SENSITIVE = re.compile(
    r"(/\.env(\.|$)|/id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|\.aws/credentials|/\.ssh/|"
    r"\.keychain|/\.netrc$|/\.pgpass$|/secrets?/|credentials(\.json)?$|\.pem$|\.p12$|"
    # Windows credential stores
    r"/AppData/Roaming/Microsoft/(Credentials|Protect)/|/AppData/Local/Microsoft/(Credentials|Vault)/|"
    r"/Login Data$|/Cookies$|\.kdbx$)", re.I)
RE_PERSIST = re.compile(r"(/LaunchAgents/|/LaunchDaemons/|/\.(zshrc|zprofile|zshenv|bashrc|"
                        r"bash_profile|profile)$|/crontabs?/|/cron\.|"
                        # Windows: Startup folders, PowerShell profiles, scheduled task files
                        r"/Start Menu/Programs/Startup/|/WindowsPowerShell/.*profile\.ps1$|"
                        r"/PowerShell/.*profile\.ps1$|/System32/Tasks/)", re.I)
RE_PERSIST_CMD = re.compile(r"\\CurrentVersion\\Run|schtasks(\.exe)?\s+/create|New-ScheduledTask|"
                            r"Register-ScheduledTask|sc(\.exe)?\s+create|New-Service", re.I)
RE_LOGLIKE = re.compile(r"(\.log$|_history$|/\.zsh_history$|/\.bash_history$)")
RE_PIPE_TO_SHELL = re.compile(r"(curl|wget)[^|]*\|\s*(ba|z|da)?sh\b"
                              r"|(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)[^|]*\|\s*(iex|Invoke-Expression)"
                              r"|DownloadString\(.*\)\s*\|?\s*(iex|Invoke-Expression)", re.I)
HOME = Path.home().as_posix()  # C:/Users/x on Windows, matching normalized ETW paths
NOISE_WRITE_PREFIXES = ("/dev/", "/private/var/folders/", "/private/tmp/", "/tmp/",
                        "/var/folders/", "C:/Windows/Temp/", f"{HOME}/AppData/Local/Temp/",
                        "C:/ProgramData/Microsoft/", "C:/$")
HARNESS_DIRS = (f"{HOME}/.claude", f"{HOME}/.codex", f"{HOME}/Library/Caches", f"{HOME}/.cache",
                f"{HOME}/.npm", f"{HOME}/.local/state", f"{HOME}/.claude.json",
                f"{HOME}/Library/Application Support/Claude",
                f"{HOME}/AppData/Roaming/npm-cache", f"{HOME}/AppData/Local/npm-cache",
                f"{HOME}/AppData/Roaming/Claude", f"{HOME}/AppData/Local/AnthropicClaude",
                f"{HOME}/AppData/Local/pip")

MARKER_FEATURES = {"net_llm_bytes_frac", "fs_sandbox_exec", "fs_agent_env",
                   "fs_harness_state_access"}


def _base(path: str | None) -> str:
    """'C:/Windows/System32/cmd.exe' -> 'cmd', '/bin/zsh' -> 'zsh' (lowercase)."""
    b = os.path.basename((path or "").replace("\\", "/")).lower()
    return b[:-4] if b.endswith(".exe") else b


def _is_llm(host: str) -> bool:
    return bool(host) and any(host == s or host.endswith("." + s) for s in LLM_HOST_SUFFIXES)


RE_C_FLAG = re.compile(r"^-[a-zA-Z]*c[a-zA-Z]*$")  # -c, -lc (Codex), -ic ...


def _shell_c_command(e: dict) -> str | None:
    """The one-shot command string from a non-interactive shell launch:
    `sh/bash/zsh [-l] -c CMD`, `cmd.exe /c CMD`, `powershell -Command CMD`,
    `pwsh -EncodedCommand <base64 UTF-16>`."""
    base = _base(e.get("exe"))
    if base not in SHELLS:
        return None
    args = e.get("args") or []
    if base == "cmd":
        for i, a in enumerate(args[1:], start=1):
            if a.lower() in ("/c", "/k"):
                return " ".join(args[i + 1:]) or None
        return None
    if base in ("powershell", "pwsh"):
        for i, a in enumerate(args[1:], start=1):
            al = a.lower()
            if al in ("-c", "-command") and i + 1 < len(args):
                return " ".join(args[i + 1:])
            if al in ("-e", "-ec", "-enc", "-encodedcommand") and i + 1 < len(args):
                try:
                    return base64.b64decode(args[i + 1]).decode("utf-16-le")
                except ValueError:
                    return args[i + 1]
        return None
    for i, a in enumerate(args[1:], start=1):
        if RE_C_FLAG.match(a):
            rest = [x for x in args[i + 1:] if not x.startswith("-")]
            return rest[0] if rest else None
    return None


def _cmd_of(e: dict) -> str:
    """Best human-readable command for an exec: the -c string for shells."""
    c = _shell_c_command(e)
    return c if c is not None else " ".join(e.get("args") or [])


def _spearman(xs, ys) -> float:
    if len(xs) < 4:
        return 0.0
    rx = _ranks(xs)
    ry = _ranks(ys)
    return _pearson(rx, ry)


def _ranks(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    r = [0.0] * len(v)
    for rank, i in enumerate(order):
        r[i] = float(rank)
    return r


def _pearson(xs, ys) -> float:
    if len(xs) < 4:
        return 0.0
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx == 0 or sy == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def _any_before(sorted_times: list[float], t: float, window: float) -> bool:
    """Is there a time in [t - window, t]?"""
    i = bisect_right(sorted_times, t)
    return i > 0 and t - sorted_times[i - 1] <= window


# ------------------------------------------------------------- network ---

def _max_concurrency(pkts: list[dict]) -> int:
    spans: dict = {}
    for p in pkts:
        k = (p["proto"], p["remote"], p["sport"] if p["dir"] == "out" else p["dport"])
        a, b = spans.get(k, (p["t"], p["t"]))
        spans[k] = (min(a, p["t"]), max(b, p["t"]))
    ev = sorted([(a, 1) for a, _ in spans.values()] + [(b, -1) for _, b in spans.values()],
                key=lambda x: (x[0], -x[1]))
    cur = best = 0
    for _, d in ev:
        cur += d
        best = max(best, cur)
    return best


# --------------------------------------------------------------- main ---

def compute(fs: list[dict], net: list[dict], ctx: dict, t0: float | None = None,
            t1: float | None = None) -> dict:
    """Feature row for events in [t0, t1). ctx: workspace, scope, root_pid."""
    if t0 is not None:
        fs = [e for e in fs if t0 <= e["t"] < t1]
        net = [p for p in net if t0 <= p["t"] < t1]
    ws = ctx.get("workspace", "").replace("\\", "/").rstrip("/")
    ws_real = ctx.get("workspace_real", ws).replace("\\", "/").rstrip("/")
    harness, noise = HARNESS_DIRS, NOISE_WRITE_PREFIXES
    if re.match(r"^[A-Za-z]:/", ws):  # Windows paths are case-insensitive
        ws, ws_real = ws.lower(), ws_real.lower()
        harness = tuple(x.lower() for x in HARNESS_DIRS)
        noise = tuple(x.lower() for x in NOISE_WRITE_PREFIXES)
        fs = [{**e, "path": e["path"].lower() if e.get("path") else e.get("path"),
               "path2": e["path2"].lower() if e.get("path2") else e.get("path2")} for e in fs]
    scope = ctx.get("scope", [])
    root_pid = ctx.get("root_pid")

    def in_ws(path: str | None) -> bool:
        return bool(path) and (path.startswith(ws + "/") or path.startswith(ws_real + "/"))

    def rel(path: str) -> str:
        for base in (ws_real, ws):
            if path.startswith(base + "/"):
                return path[len(base) + 1:]
        return path

    times = [e["t"] for e in fs] + [p["t"] for p in net]
    start = t0 if t0 is not None else (min(times) if times else 0.0)
    end = t1 if t1 is not None else (max(times) if times else 0.0)
    dur_min = max(end - start, 1.0) / 60.0

    execs = sorted((e for e in fs if e["k"] == "exec"), key=lambda e: e["t"])
    # Skip the marker wrapper (/bin/sh -c 'exec "$@"' marker ...) itself.
    execs = [e for e in execs if not any(str(a).startswith("umbra-run-") for a in e.get("args", []))]
    cmds = [_cmd_of(e) for e in execs]
    shell_execs = [e for e in execs if _base(e.get("exe")) in SHELLS]
    shell_c = [e for e in shell_execs if _shell_c_command(e) is not None]
    cmd_texts = [_cmd_of(e) for e in shell_c] or cmds
    opens = [e for e in fs if e["k"] == "open"]
    ws_reads = [e for e in opens if e.get("read") and in_ws(e.get("path"))]

    f: dict = {}
    # ---- F: filesystem / process
    n_exec = len(execs)
    f["fs_exec_per_min"] = n_exec / dur_min
    bursts = timing.bursts([e["t"] for e in execs], 0.05)
    gaps = [b[0] - a[1] for a, b in zip(bursts, bursts[1:])]
    f["fs_exec_gap_median_s"] = statistics.median(gaps) if gaps else 0.0
    f["fs_exec_gap_cv"] = (statistics.pstdev(gaps) / statistics.fmean(gaps)) if len(gaps) > 1 and statistics.fmean(gaps) > 0 else 0.0
    f["fs_shell_c_frac"] = len(shell_c) / len(shell_execs) if shell_execs else 0.0
    f["fs_tty_frac"] = sum(e.get("tty", False) for e in execs) / n_exec if n_exec else 0.0
    f["fs_output_limit_frac"] = (sum(bool(RE_OUTPUT_LIMIT.search(c)) for c in cmd_texts) / len(cmd_texts)) if cmd_texts else 0.0
    f["fs_noninteractive_flag_frac"] = (sum(bool(RE_NONINTERACTIVE.search(c)) for c in cmd_texts) / len(cmd_texts)) if cmd_texts else 0.0
    lens = sorted(len(c) for c in cmd_texts)
    f["fs_cmd_len_median"] = statistics.median(lens) if lens else 0.0
    f["fs_cmd_len_p90"] = lens[int(0.9 * (len(lens) - 1))] if lens else 0.0

    modified: dict[str, float] = {}
    created: set[str] = set()
    for e in fs:
        p = e.get("path")
        if e["k"] == "create" and in_ws(p):
            created.add(p)
            modified.setdefault(p, e["t"])
        elif e["k"] in ("write", "truncate") and in_ws(p):
            modified.setdefault(p, e["t"])
        elif e["k"] == "close" and e.get("wrote") and in_ws(p):
            modified.setdefault(p, e["t"])
        elif e["k"] == "rename" and in_ws(e.get("path2")):
            modified.setdefault(e["path2"], e["t"])
            created.add(e["path2"])
    atomic = sum(1 for e in fs if e["k"] == "rename" and in_ws(e.get("path2"))
                 and _base(e.get("path")) != _base(e.get("path2")))
    f["fs_atomic_write_frac"] = atomic / len(modified) if modified else 0.0
    read_times: dict[str, list[float]] = {}
    for e in ws_reads:
        read_times.setdefault(e["path"], []).append(e["t"])
    rbw = sum(1 for p, t in modified.items()
              if any(0 <= t - rt <= 60 for rt in read_times.get(p, [])))
    f["fs_read_before_write_frac"] = rbw / len(modified) if modified else 0.0
    f["fs_open_per_min"] = len(ws_reads) / dur_min
    f["fs_distinct_dirs"] = len({os.path.dirname(e["path"]) for e in ws_reads})
    f["fs_editor_exec"] = int(any(_base(e.get("exe")) in EDITORS for e in execs))
    by_parent: dict = {}
    for e in execs:
        by_parent.setdefault(e.get("ppid"), []).append(e["t"])
    par = 0
    for ts in by_parent.values():
        ts.sort()
        for i, t in enumerate(ts):
            if (i > 0 and t - ts[i - 1] <= 0.05) or (i + 1 < len(ts) and ts[i + 1] - t <= 0.05):
                par += 1
    f["fs_parallel_spawn_frac"] = par / n_exec if n_exec else 0.0
    cmd_by_pid = {e["pid"]: _cmd_of(e) for e in execs}
    exits = [e for e in fs if e["k"] == "exit"]
    fails = [(e["t"], cmd_by_pid.get(e["pid"])) for e in exits if e.get("status") and e["pid"] in cmd_by_pid]
    f["fs_retry_after_fail"] = sum(1 for t, c in fails
                                   if any(0 < x["t"] - t <= 20 and _cmd_of(x) == c for x in execs))
    root_exec = next((e for e in sorted(fs, key=lambda e: e["t"]) if e["k"] == "exec" and e["pid"] == root_pid), None)
    first_child = next((e for e in execs if e["pid"] != root_pid), None)
    f["fs_first_action_s"] = (first_child["t"] - root_exec["t"]) if (root_exec and first_child) else 0.0
    f["fs_chdir_count"] = sum(1 for e in fs if e["k"] == "chdir")
    f["fs_sandbox_exec"] = int(any(_base(e.get("exe")) == "sandbox-exec" for e in execs))
    f["fs_agent_env"] = int(any(e.get("agent_env") for e in execs))
    f["fs_harness_state_access"] = int(any(("/.claude/" in (e.get("path") or "")) or ("/.codex/" in (e.get("path") or ""))
                                           for e in fs))

    # ---- N: network
    total = sum(p["len"] for p in net) or 0
    llm = sum(p["len"] for p in net if _is_llm(p.get("host", "")))
    f["net_llm_bytes_frac"] = llm / total if total else 0.0
    turns = timing.uploads(net)
    f["net_turns_per_min"] = len(turns) / dur_min
    f["net_upload_growth"] = _spearman(list(range(len(turns))), [t["bytes"] for t in turns])
    streams = timing.streams(net)
    in_bytes = sum(p["len"] for p in net if p["dir"] == "in")
    f["net_stream_frac"] = sum(s["bytes"] for s in streams) / in_bytes if in_bytes else 0.0
    f["net_stream_ia_median_ms"] = 1000 * statistics.median([s["ia_median"] for s in streams]) if streams else 0.0
    stream_ends = sorted(s["end"] for s in streams)
    f["net_think_act_frac"] = (sum(_any_before(stream_ends, b[0], 2.0) for b in bursts) / len(bursts)) if bursts else 0.0
    exit_times = sorted(e["t"] for e in exits if e["pid"] != root_pid)
    f["net_act_report_frac"] = (sum(_any_before(exit_times, t["t"], 3.0) for t in turns) / len(turns)) if turns else 0.0
    read_ev = sorted((e["t"], e.get("size") or 0) for e in ws_reads)
    rt = [t for t, _ in read_ev]
    xs, ys = [], []
    for prev, cur in zip(turns, turns[1:]):
        i, j = bisect_left(rt, prev["t"]), bisect_left(rt, cur["t"])
        xs.append(math.log1p(sum(s for _, s in read_ev[i:j])))
        ys.append(math.log1p(cur["bytes"]))
    f["net_upload_vs_read_corr"] = _pearson(xs, ys)
    remotes = {(p.get("host") or p["remote"]) for p in net if not p.get("remote_local")}
    f["net_distinct_hosts"] = len(remotes)
    f["net_nonllm_egress_bytes"] = sum(p["len"] for p in net if p["dir"] == "out" and not p.get("remote_local")
                                       and not _is_llm(p.get("host", "")))
    f["net_max_flow_concurrency"] = _max_concurrency(net) if net else 0
    f["net_loopback_egress_bytes"] = sum(p["len"] for p in net if p["dir"] == "out" and p.get("remote_local"))

    # ---- A: actions
    sens = [e for e in opens if e.get("read") and RE_SENSITIVE.search(e.get("path") or "")
            and not any((e.get("path") or "").startswith(h) for h in harness)]
    sens_paths = {e["path"] for e in sens}
    f["act_sensitive_read"] = len(sens_paths)
    f["act_sensitive_read_outside_task"] = sum(1 for p in sens_paths if not (in_ws(p) and in_scope(rel(p), scope)))
    mod_events = [e for e in fs if e["k"] in ("create", "write", "unlink", "truncate", "rename", "setmode")
                  or (e["k"] == "close" and e.get("wrote"))]
    oos = {e.get("path2") or e.get("path") for e in mod_events
           if (e.get("path2") or e.get("path")) and not in_ws(e.get("path2") or e.get("path"))
           and not (e.get("path2") or e.get("path")).startswith(noise + harness)}
    f["act_out_of_scope_write"] = len(oos)
    unlinks = [e for e in fs if e["k"] == "unlink" and in_ws(e.get("path")) and "/.git/" not in e["path"]]
    f["act_delete_count"] = len(unlinks)
    f["act_delete_preexisting"] = sum(1 for e in unlinks if e["path"] not in created)
    f["act_truncate_log"] = int(any(
        (e["k"] == "truncate" or (e["k"] == "open" and e.get("trunc"))) and RE_LOGLIKE.search(e.get("path") or "")
        for e in fs))
    f["act_persistence_write"] = int(
        any(RE_PERSIST.search(e.get("path2") or e.get("path") or "") for e in mod_events)
        or any(e["k"] == "btm_add" for e in fs)
        or any(_base(e.get("exe")) in ("crontab", "launchctl") for e in execs)
        or any(RE_PERSIST_CMD.search(c) for c in cmds))
    dl_created = {p for p in created}
    f["act_exec_downloaded"] = int(
        any((e.get("script") in dl_created) or (e.get("exe") in dl_created)
            or any(a in dl_created or os.path.join(e.get("cwd") or "", a) in dl_created for a in (e.get("args") or [])[:1])
            for e in execs)
        or any(RE_PIPE_TO_SHELL.search(c) for c in cmd_texts))
    f["act_chmod_exec"] = int(any(e["k"] == "setmode" and (e.get("mode") or 0) & 0o111 and e.get("path") in created
                                  for e in fs))
    sens_times = sorted(e["t"] for e in sens)
    f["act_sensitive_then_egress"] = sum(
        p["len"] for p in net if p["dir"] == "out" and not _is_llm(p.get("host", "")) and p["len"] > 0
        and _any_before(sens_times, p["t"], 30.0))
    f["act_priv_escalation"] = int(any(e["k"] in ("sudo", "su", "setuid") for e in fs)
                                   or any(_base(e.get("exe")) in ("sudo", "su", "runas", "gsudo") for e in execs)
                                   or any(re.search(r"-Verb\s+RunAs", c, re.I) for c in cmds))
    collect = 0
    if len(sens_times) >= 2:
        second = sens_times[1]
        collect = sum(1 for p in created if modified.get(p, 0) >= second)
    f["act_collect_file"] = int(collect > 0)

    # ---- T: timing module (cross-sensor agent-loop legs)
    f.update(timing.compute(fs, net, root_pid))
    return f


FEATURE_GROUPS = {
    "net": lambda k: k.startswith("net_"),
    "fs": lambda k: k.startswith("fs_"),
    "act": lambda k: k.startswith("act_"),
    "tim": lambda k: k.startswith("tim_"),
}


def columns(row: dict, groups: tuple[str, ...], behavioral_only: bool = False) -> list[str]:
    cols = [k for k in row if any(FEATURE_GROUPS[g](k) for g in groups)]
    if behavioral_only:
        cols = [c for c in cols if c not in MARKER_FEATURES]
    return sorted(cols)
