"""Timing detection module: one clock across network and filesystem.

eslogger (ns) and pktap (us) both stamp events from the same system clock.
On this Mac a curl's first SYN lands 25 ms after its exec event and every
packet falls inside its exec->exit window, so the two streams can be compared
at millisecond resolution.

That lets us rebuild the agent loop and time each leg of it:

    upload --ttft--> stream start --gen--> stream end --dispatch--> cmd start
        --tool--> cmd end --report--> next upload

The key leg is **dispatch**: a harness starts the tool within milliseconds
of the model's last token. A human, even one pasting from a chatbot, needs
seconds and is irregular. Dispatch stays measurable after an attacker hides
domains, env vars and binaries, because the model has to finish answering
before the tool can run.

Used by features.py (the `tim_*` columns) and by `umbra-train timeline`.
"""

from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right

DISPATCH_WINDOW_S = 5.0   # a command this soon after a stream ends counts as dispatched by it
REPORT_WINDOW_S = 10.0    # an upload this soon after a command ends counts as reporting it


# ------------------------------------------------------------ primitives ---

def bursts(times: list[float], gap: float) -> list[tuple[float, float, int]]:
    """Group sorted times into bursts separated by > gap. (start, end, count)."""
    out: list[tuple[float, float, int]] = []
    for t in times:
        if out and t - out[-1][1] <= gap:
            s, _, n = out[-1]
            out[-1] = (s, t, n + 1)
        else:
            out.append((t, t, 1))
    return out


def uploads(pkts: list[dict]) -> list[dict]:
    """Outbound bursts (>=1 KB within 300 ms gaps) on non-local TLS flows.
    One per agent 'turn': the harness sending context to the model."""
    outs = sorted((p for p in pkts if p["dir"] == "out" and p["len"] > 0
                   and not p.get("remote_local") and p["dport"] == 443), key=lambda p: p["t"])
    res = []
    times = [p["t"] for p in outs]
    for s, e, _ in bursts(times, 0.3):
        i, j = bisect_left(times, s), bisect_right(times, e)
        size = sum(p["len"] for p in outs[i:j])
        if size >= 1000:
            hosts = {p.get("host") or p.get("remote") for p in outs[i:j]}
            res.append({"t": s, "end": e, "bytes": size, "host": ",".join(sorted(h for h in hosts if h))})
    return res


def streams(pkts: list[dict]) -> list[dict]:
    """Inbound token-stream trains: >=20 packets, 5-300 ms apart, per flow."""
    flows: dict = {}
    for p in sorted(pkts, key=lambda p: p["t"]):
        if p["dir"] == "in" and p["len"] > 0:
            flows.setdefault((p.get("remote"), p["sport"], p["dport"]), []).append(p)
    trains = []
    for fp in flows.values():
        cur = [fp[0]]
        for prev, p in zip(fp, fp[1:]):
            if 0.005 <= p["t"] - prev["t"] <= 0.3:
                cur.append(p)
            else:
                if len(cur) >= 20:
                    trains.append(cur)
                cur = [p]
        if len(cur) >= 20:
            trains.append(cur)
    out = []
    for s in trains:
        ia = [b["t"] - a["t"] for a, b in zip(s, s[1:])]
        out.append({"t": s[0]["t"], "end": s[-1]["t"], "bytes": sum(p["len"] for p in s),
                    "packets": len(s), "ia_median": statistics.median(ia),
                    "host": s[0].get("host") or s[0].get("remote")})
    return sorted(out, key=lambda s: s["t"])


def commands(fs: list[dict], root_pid: int | None) -> list[dict]:
    """Command launches: exec bursts (50 ms) below the root, with exit times."""
    execs = sorted((e for e in fs if e["k"] == "exec" and e["pid"] != root_pid
                    and not any(str(a).startswith("umbra-run-") for a in e.get("args", []))),
                   key=lambda e: e["t"])
    exit_at = {}
    for e in fs:
        if e["k"] == "exit":
            exit_at.setdefault(e["pid"], e["t"])
    out = []
    times = [e["t"] for e in execs]
    for s, e, _ in bursts(times, 0.05):
        i, j = bisect_left(times, s), bisect_right(times, e)
        group = execs[i:j]
        ends = [exit_at[x["pid"]] for x in group if x["pid"] in exit_at]
        out.append({"t": s, "end": max(ends) if ends else None, "n": len(group),
                    "argv": " ".join(group[0].get("args") or [])[:160]})
    return out


def _after(sorted_times: list[float], t: float, window: float) -> int | None:
    """Index of the first time in (t, t + window], or None."""
    i = bisect_right(sorted_times, t)
    return i if i < len(sorted_times) and sorted_times[i] - t <= window else None


def _before(sorted_times: list[float], t: float, window: float) -> int | None:
    """Index of the last time in [t - window, t], or None."""
    i = bisect_right(sorted_times, t) - 1
    return i if i >= 0 and t - sorted_times[i] <= window else None


# ---------------------------------------------------------------- cycles ---

def cycles(fs: list[dict], net: list[dict], root_pid: int | None) -> dict:
    """Rebuild the agent loop and time every leg. Returns lists of legs (s)."""
    ups = uploads(net)
    sts = streams(net)
    cmds = commands(fs, root_pid)
    up_t = [u["t"] for u in ups]
    st_t = [s["t"] for s in sts]
    cmd_t = [c["t"] for c in cmds]
    cmd_end = sorted(c["end"] for c in cmds if c["end"] is not None)

    legs = {"ttft": [], "gen": [], "dispatch": [], "tool": [], "report": [], "period": []}
    for u in ups:
        k = _after(st_t, u["end"], 30.0)
        if k is not None:
            legs["ttft"].append(sts[k]["t"] - u["end"])
    for s in sts:
        legs["gen"].append(s["end"] - s["t"])
        k = _after(cmd_t, s["end"], DISPATCH_WINDOW_S)
        if k is not None:
            legs["dispatch"].append(cmds[k]["t"] - s["end"])
    for c in cmds:
        if c["end"] is not None:
            legs["tool"].append(c["end"] - c["t"])
    for u in ups:
        k = _before(cmd_end, u["t"], REPORT_WINDOW_S)
        if k is not None:
            legs["report"].append(u["t"] - cmd_end[k])
    legs["period"] = [b - a for a, b in zip(up_t, up_t[1:])]

    # A complete cycle: upload -> stream -> dispatched command -> reported by the next upload.
    complete = 0
    for i, u in enumerate(ups[:-1]):
        k = _after(st_t, u["end"], 30.0)
        if k is None:
            continue
        c = _after(cmd_t, sts[k]["end"], DISPATCH_WINDOW_S)
        if c is None or cmds[c]["end"] is None:
            continue
        nxt = ups[i + 1]["t"]
        if 0 <= nxt - cmds[c]["end"] <= REPORT_WINDOW_S:
            complete += 1
    return {"legs": legs, "complete": complete, "uploads": ups, "streams": sts, "commands": cmds}


# -------------------------------------------------------------- features ---

def _med(v):
    return statistics.median(v) if v else 0.0


def _cv(v):
    if len(v) < 2:
        return 0.0
    m = statistics.fmean(v)
    return statistics.pstdev(v) / m if m > 0 else 0.0


def _burstiness(times: list[float]) -> float:
    """Goh-Barabasi burstiness of inter-event gaps: -1 periodic, 0 random, ~1 bursty."""
    gaps = [b - a for a, b in zip(times, times[1:])]
    if len(gaps) < 2:
        return 0.0
    m, s = statistics.fmean(gaps), statistics.pstdev(gaps)
    return (s - m) / (s + m) if (s + m) > 0 else 0.0


def compute(fs: list[dict], net: list[dict], root_pid: int | None) -> dict:
    """`tim_*` feature columns. All behavioral: no domains or names used."""
    c = cycles(fs, net, root_pid)
    L = c["legs"]
    cmds = c["commands"]
    st_end = sorted(s["end"] for s in c["streams"])
    net_t = sorted(p["t"] for p in net if not p.get("remote_local"))
    quiet = sum(1 for x in cmds if _before(net_t, x["t"], 10.0) is None)
    return {
        "tim_cycles": c["complete"],
        "tim_cycle_cmd_frac": (c["complete"] / len(cmds)) if cmds else 0.0,
        "tim_ttft_median_s": _med(L["ttft"]),
        "tim_gen_median_s": _med(L["gen"]),
        "tim_dispatch_median_ms": 1000 * _med(L["dispatch"]),
        "tim_dispatch_cv": _cv(L["dispatch"]),
        "tim_dispatched_cmd_frac": (sum(1 for x in cmds if _before(st_end, x["t"], DISPATCH_WINDOW_S) is not None) / len(cmds)) if cmds else 0.0,
        "tim_report_median_ms": 1000 * _med(L["report"]),
        "tim_report_cv": _cv(L["report"]),
        "tim_period_median_s": _med(L["period"]),
        "tim_period_cv": _cv(L["period"]),
        "tim_tool_median_s": _med(L["tool"]),
        "tim_cmd_burstiness": _burstiness([x["t"] for x in cmds]),
        "tim_net_quiet_cmd_frac": (quiet / len(cmds)) if cmds else 0.0,
    }


# -------------------------------------------------------------- timeline ---

def timeline(fs: list[dict], net: list[dict], root_pid: int | None) -> list[dict]:
    """Merged, annotated timeline for one run (for `umbra-train timeline`,
    the dashboard and the demo video)."""
    c = cycles(fs, net, root_pid)
    rows = []
    st_end = [s["end"] for s in c["streams"]]
    cmd_end = sorted(x["end"] for x in c["commands"] if x["end"] is not None)
    up_end = [u["end"] for u in c["uploads"]]
    for u in c["uploads"]:
        r = _before(cmd_end, u["t"], REPORT_WINDOW_S)
        rows.append({"t": u["t"], "src": "net", "what": "upload",
                     "detail": f"{u['bytes'] / 1024:.1f} KB -> {u['host'] or '?'}",
                     "leg": ("report", u["t"] - cmd_end[r]) if r is not None else None})
    for s in c["streams"]:
        u = _before(up_end, s["t"], 30.0)
        rows.append({"t": s["t"], "src": "net", "what": "stream start",
                     "detail": f"{s['packets']} pkts, {s['ia_median'] * 1000:.0f} ms apart",
                     "leg": ("ttft", s["t"] - up_end[u]) if u is not None else None})
        rows.append({"t": s["end"], "src": "net", "what": "stream end",
                     "detail": f"{(s['end'] - s['t']):.1f} s of tokens", "leg": None})
    for x in c["commands"]:
        k = _before(st_end, x["t"], DISPATCH_WINDOW_S)
        rows.append({"t": x["t"], "src": "fs", "what": "cmd start", "detail": x["argv"],
                     "leg": ("dispatch", x["t"] - st_end[k]) if k is not None else None})
        if x["end"] is not None:
            rows.append({"t": x["end"], "src": "fs", "what": "cmd end", "detail": "",
                         "leg": ("tool", x["end"] - x["t"])})
    for e in fs:
        if (e.get("path") or "").startswith("/dev/"):
            continue
        if e["k"] in ("create", "unlink", "rename") or (e["k"] == "open" and e.get("wrote")):
            rows.append({"t": e["t"], "src": "fs", "what": e["k"], "detail": e.get("path2") or e.get("path") or "",
                         "leg": None})
    rows.sort(key=lambda r: r["t"])
    return rows


def format_timeline(rows: list[dict], t0: float | None = None, limit: int = 400) -> str:
    if not rows:
        return "(no events)"
    t0 = rows[0]["t"] if t0 is None else t0
    out = []
    for r in rows[:limit]:
        leg = ""
        if r["leg"]:
            name, v = r["leg"]
            leg = f"  [{name} {v * 1000:.0f} ms]" if v < 10 else f"  [{name} {v:.1f} s]"
        out.append(f"+{r['t'] - t0:8.3f}s  {r['src']:3}  {r['what']:12} {r['detail'][:90]}{leg}")
    if len(rows) > limit:
        out.append(f"... {len(rows) - limit} more")
    return "\n".join(out)
