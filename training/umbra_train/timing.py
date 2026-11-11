"""Timing detection module: one clock across network and filesystem.

eslogger (ns) and pktap (us) both stamp events from the same system clock.
On this Mac a curl's first SYN lands 25 ms after its exec event and every
packet falls inside its exec->exit window, so the two streams can be compared
at millisecond resolution.

That lets us rebuild the agent loop and time each leg of it:

    upload --ttft--> response --gen--> last model packet --dispatch--> cmd start
        --tool--> cmd end --report--> next upload

The key leg is **dispatch**: a harness starts the tool within milliseconds
of the model's last packet (19-35 ms for Claude, 11-18 ms for Codex on the
first real batch). A human, even one pasting from a chatbot, needs
seconds and is irregular. Dispatch stays measurable after an attacker hides
domains, env vars and binaries, because the model has to finish answering
before the tool can run.

Used by features.py (the `tim_*` columns) and by `umbra-train timeline`.
"""

from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right

DISPATCH_WINDOW_S = 5.0   # a command this soon after model traffic counts as dispatched by it
REPORT_WINDOW_S = 10.0    # an upload this soon after a command ends counts as reporting it
RESPONSE_GAP_S = 0.3      # inbound silence that ends one response burst


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


def _model_flow(p: dict) -> bool:
    """Non-local TLS: where a harness talks to its model (or anything HTTPS)."""
    return not p.get("remote_local") and (p["dport"] if p["dir"] == "out" else p["sport"]) == 443


def _flow(p: dict) -> tuple:
    """(remote address, local port): one TCP connection, either direction."""
    return (p.get("remote"), p["sport"] if p["dir"] == "out" else p["dport"])


def _per_flow(pkts: list[dict], direction: str) -> dict:
    flows: dict = {}
    for p in sorted(pkts, key=lambda p: p["t"]):
        if p["dir"] == direction and p["len"] > 0 and _model_flow(p):
            flows.setdefault(_flow(p), []).append(p)
    return flows


def uploads(pkts: list[dict]) -> list[dict]:
    """Outbound bursts (>=1 KB, 300 ms gaps) per connection: one per agent
    'turn', the harness sending context to the model."""
    res = []
    for flow, ps in _per_flow(pkts, "out").items():
        times = [p["t"] for p in ps]
        for s, e, _ in bursts(times, 0.3):
            i, j = bisect_left(times, s), bisect_right(times, e)
            size = sum(p["len"] for p in ps[i:j])
            if size >= 1000:
                res.append({"t": s, "end": e, "bytes": size, "flow": flow,
                            "host": ps[i].get("host") or ps[i].get("remote") or ""})
    return sorted(res, key=lambda u: u["t"])


def responses(pkts: list[dict]) -> list[dict]:
    """Inbound bursts per connection, split by >300 ms of silence.

    Measured on the first real batch: Claude's answers arrive as a handful of
    chunks ~45 ms apart (the token cadence). Codex keeps one connection busy
    with bursts every few hundred ms. An earlier rule ("20+ packets 5-300 ms
    apart") matched neither, so there is no minimum size here. `chunk_ms` is
    the median gap between chunks inside the burst (gaps of 5-300 ms only;
    sub-5 ms gaps are TCP segments of one chunk)."""
    res = []
    for flow, ps in _per_flow(pkts, "in").items():
        times = [p["t"] for p in ps]
        for s, e, n in bursts(times, RESPONSE_GAP_S):
            i, j = bisect_left(times, s), bisect_right(times, e)
            gaps = [b - a for a, b in zip(times[i:j], times[i + 1:j]) if 0.005 <= b - a <= 0.3]
            res.append({"t": s, "end": e, "bytes": sum(p["len"] for p in ps[i:j]), "packets": n,
                        "chunk_ms": 1000 * statistics.median(gaps) if gaps else 0.0, "flow": flow,
                        "host": ps[i].get("host") or ps[i].get("remote") or ""})
    return sorted(res, key=lambda r: r["t"])


streams = responses  # older name, still used by features.py


def model_flows(pkts: list[dict]) -> set:
    """Connections that carried at least one upload burst (>=1 KB). That's
    what a model conversation looks like; a download, a git fetch or an idle
    keep-alive on port 443 doesn't qualify."""
    return {u["flow"] for u in uploads(pkts)}


def inbound_times(pkts: list[dict], flows: set | None = None) -> list[float]:
    flows = model_flows(pkts) if flows is None else flows
    return sorted(p["t"] for p in pkts if p["dir"] == "in" and p["len"] > 0 and _model_flow(p)
                  and _flow(p) in flows)


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
    """Index of the last time in [t - window, t), or None."""
    i = bisect_left(sorted_times, t) - 1
    return i if i >= 0 and t - sorted_times[i] <= window else None


# ---------------------------------------------------------------- cycles ---

def cycles(fs: list[dict], net: list[dict], root_pid: int | None) -> dict:
    """Rebuild the agent loop and time every leg (seconds).

    dispatch = command start - last inbound model packet before it. Anchored on
    the last packet, not a "stream end", because that's what survives both
    Claude's chunky responses and Codex's always-busy connection.
    """
    ups = uploads(net)
    mflows = {u["flow"] for u in ups}
    resp = [r for r in responses(net) if r["flow"] in mflows]
    cmds = commands(fs, root_pid)
    in_t = inbound_times(net, mflows)
    up_t = [u["t"] for u in ups]
    up_end = sorted(u["end"] for u in ups)
    cmd_end = sorted(c["end"] for c in cmds if c["end"] is not None)
    in_by_flow: dict = {}
    for p in net:
        if p["dir"] == "in" and p["len"] > 0 and _model_flow(p) and _flow(p) in mflows:
            in_by_flow.setdefault(_flow(p), []).append(p["t"])
    for v in in_by_flow.values():
        v.sort()

    legs = {"ttft": [], "gen": [], "dispatch": [], "tool": [], "report": [], "period": [], "chunk_ms": []}
    for u in ups:
        k = _after(in_by_flow.get(u["flow"], []), u["end"], 30.0)
        if k is not None:
            legs["ttft"].append(in_by_flow[u["flow"]][k] - u["end"])
    for r in resp:
        legs["gen"].append(r["end"] - r["t"])
        if r["chunk_ms"]:
            legs["chunk_ms"].append(r["chunk_ms"])
    complete = 0
    for c in cmds:
        k = _before(in_t, c["t"], DISPATCH_WINDOW_S)
        if k is not None:
            c["dispatch"] = c["t"] - in_t[k]
            legs["dispatch"].append(c["dispatch"])
        if c["end"] is not None:
            legs["tool"].append(c["end"] - c["t"])
        # complete cycle: an upload before the answer, the answer dispatched
        # this command, and the next upload reported its result
        if k is not None and c["end"] is not None and _before(up_end, in_t[k], 30.0) is not None:
            n = _after(up_t, c["end"] - 1e-9, REPORT_WINDOW_S)
            if n is not None:
                complete += 1
    for u in ups:
        k = _before(cmd_end, u["t"], REPORT_WINDOW_S)
        if k is not None:
            legs["report"].append(u["t"] - cmd_end[k])
    legs["period"] = [b - a for a, b in zip(up_t, up_t[1:])]
    return {"legs": legs, "complete": complete, "uploads": ups, "responses": resp,
            "streams": resp, "commands": cmds, "inbound_times": in_t}


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
    net_t = sorted(p["t"] for p in net if not p.get("remote_local"))
    quiet = sum(1 for x in cmds if _before(net_t, x["t"], 10.0) is None)
    return {
        "tim_cycles": c["complete"],
        "tim_cycle_cmd_frac": (c["complete"] / len(cmds)) if cmds else 0.0,
        "tim_ttft_median_s": _med(L["ttft"]),
        "tim_gen_median_s": _med(L["gen"]),
        "tim_chunk_median_ms": _med(L["chunk_ms"]),
        "tim_dispatch_median_ms": 1000 * _med(L["dispatch"]),
        "tim_dispatch_p90_ms": 1000 * (sorted(L["dispatch"])[int(0.9 * (len(L["dispatch"]) - 1))] if L["dispatch"] else 0.0),
        "tim_dispatch_cv": _cv(L["dispatch"]),
        "tim_dispatched_cmd_frac": (len(L["dispatch"]) / len(cmds)) if cmds else 0.0,
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
    cmd_end = sorted(x["end"] for x in c["commands"] if x["end"] is not None)
    up_end_by_flow: dict = {}
    for u in c["uploads"]:
        up_end_by_flow.setdefault(u["flow"], []).append(u["end"])
    for u in c["uploads"]:
        r = _before(cmd_end, u["t"], REPORT_WINDOW_S)
        rows.append({"t": u["t"], "src": "net", "what": "upload",
                     "detail": f"{u['bytes'] / 1024:.1f} KB -> {u['host'] or '?'}",
                     "leg": ("report", u["t"] - cmd_end[r]) if r is not None else None})
    for s_ in c["responses"]:
        if s_["bytes"] < 200:
            continue  # acks / keepalives
        ue = up_end_by_flow.get(s_["flow"], [])
        k = _before(ue, s_["t"], 30.0)
        cad = f", chunks {s_['chunk_ms']:.0f} ms apart" if s_["chunk_ms"] else ""
        rows.append({"t": s_["t"], "src": "net", "what": "response",
                     "detail": f"{s_['bytes'] / 1024:.1f} KB in {s_['end'] - s_['t']:.2f} s{cad}",
                     "leg": ("ttft", s_["t"] - ue[k]) if k is not None else None})
    for x in c["commands"]:
        rows.append({"t": x["t"], "src": "fs", "what": "cmd start", "detail": x["argv"].replace("\n", " "),
                     "leg": ("dispatch", x["dispatch"]) if "dispatch" in x else None})
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
