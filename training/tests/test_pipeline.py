"""Tests for the parts of the pipeline that don't need root.

The eslogger fixture is real output from this Mac (env and username scrubbed),
so the byte-level sniffers are tested against the true, random key order.
"""

import copy
import importlib.util
import io
import json
from pathlib import Path

import pytest

from umbra_train import features, ingest
from umbra_train.config import TEMPLATE_DIR
from umbra_train.lab import make_workspace, run_checks
from umbra_train.scenarios import load_all

FIX = Path(__file__).parent / "fixtures"
REAL = [json.loads(x) for x in (FIX / "eslogger_real_samples.jsonl").read_text().splitlines()]
REAL_RAW = (FIX / "eslogger_real_samples.jsonl").read_bytes().splitlines()

spec = importlib.util.spec_from_file_location(
    "sensor", Path(__file__).parents[1] / "umbra_train" / "capture" / "sensor.py")
sensor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sensor)


def _dump(ev):  # eslogger style: compact, escaped slashes
    return json.dumps(ev, separators=(",", ":")).replace("/", "\\/").encode()


def _sample(kind):
    return copy.deepcopy(next(e for e in REAL if kind in e["event"]))


def _set_pid(ev, pid, ppid=1):
    ev["process"]["audit_token"]["pid"] = pid
    ev["process"]["ppid"] = ppid
    return ev


# ---------------------------------------------------------------- sensor ---

def test_sniffers_agree_with_json_on_real_events():
    for raw, ev in zip(REAL_RAW, REAL):
        assert sensor.sniff_event_key(raw) == next(iter(ev["event"]))
        assert sensor.sniff_process_pid(raw) == ev["process"]["audit_token"]["pid"]


def test_tree_filter_keeps_only_marked_tree():
    marker = "umbra-run-test123"
    root, child, other = 50001, 50002, 50003
    ex = _set_pid(_sample("exec"), root)
    ex["event"]["exec"]["args"] = ["/bin/sh", "-c", 'exec "$@"', marker, "claude", "-p", "hi"]
    fk = _set_pid(_sample("fork"), root)
    fk["event"]["fork"]["child"]["audit_token"]["pid"] = child
    w_child = _set_pid(_sample("write"), child, root)
    w_other = _set_pid(_sample("write"), other)
    op_other = _set_pid(_sample("open"), other)
    ex_other = _set_pid(_sample("exec"), other)
    ext = _set_pid(_sample("exit"), child, root)
    w_after_exit = _set_pid(_sample("write"), child, root)
    stream = [_dump(e) for e in (ex_other, ex, fk, w_child, w_other, op_other, ext, w_after_exit)]
    tree, proc = io.BytesIO(), io.BytesIO()
    t = sensor.TreeTracker(marker)
    stats = sensor.filter_stream(stream, t, tree, proc)
    kept = [json.loads(x) for x in tree.getvalue().splitlines()]
    kinds = [(next(iter(e["event"])), e["process"]["audit_token"]["pid"]) for e in kept]
    assert kinds == [("exec", root), ("fork", root), ("write", child), ("exit", child)]
    assert t.root == root and t.summary()["pids"] == [root, child]
    assert stats["proc"] == 4  # exec, exec, fork, exit all go to proc_all
    assert len(proc.getvalue().splitlines()) == 4


# ---------------------------------------------------------------- ingest ---

def test_normalize_every_real_event():
    for ev in REAL:
        n = ingest.normalize_es_event(ev)
        key = next(iter(ev["event"]))
        if key == "uipc_connect":
            assert n is None
            continue
        assert n["t"] > 1.7e9 and n["pid"] > 0
        if key in ("open", "write", "unlink", "create"):
            assert n["path"].startswith("/"), (key, n)
        if key == "rename":
            assert n["path"] and n["path2"]
        if key == "exec":
            assert n["args"] and n["cwd"].startswith("/")


@pytest.mark.parametrize("line,expect", [
    ("1762400000.123456 (proc claude:4242, out) IP 192.168.1.5.53211 > 160.79.104.10.443: tcp 517",
     {"pid": 4242, "proc": "claude", "dir": "out", "dport": 443, "len": 517, "proto": "tcp"}),
    ("1762400000.2 (en0, proc Google Chrome Helper:977:ABCD, svc BE, in, so) IP6 2606:4700::1.443 > fe80::1.50000: tcp 1400",
     {"pid": 977, "proc": "Google Chrome Helper", "dir": "in", "sport": 443, "len": 1400}),
    ("1762400000.3 (lo0, proc curl:88, eproc curl:88, out) IP 127.0.0.1.60000 > 127.0.0.1.8765: tcp 240",
     {"pid": 88, "epid": 88, "dir": "out", "dst": "127.0.0.1", "dport": 8765}),
    ("1762400000.4 (proc mDNSResponder:300, out) IP 192.168.1.5.5353 > 1.1.1.1.53: UDP, length 45",
     {"pid": 300, "proto": "udp", "len": 45}),
])
def test_parse_tcpdump_line(line, expect):
    p = ingest.parse_tcpdump_line(line)
    for k, v in expect.items():
        assert p[k] == v, (k, p)


def test_parse_tcpdump_line_rejects_garbage():
    assert ingest.parse_tcpdump_line("reading from file net.pcapng, link-type PKTAP") is None


# -------------------------------------------------------------- features ---

WS = "/Users/user/UmbraLab/sandboxes/run1"


def _agent_session():
    """Agent-shaped: model streams, then a no-TTY `sh -c` command, then upload."""
    fs, net = [], []
    t = 1000.0
    fs.append({"t": t, "k": "exec", "pid": 10, "ppid": 1, "exe": "/bin/sh", "tty": False,
               "args": ["/bin/sh", "-c", 'exec "$@"', "umbra-run-x", "claude"], "agent_env": []})
    pid = 100
    for turn in range(8):
        # inbound token stream 40 packets, 30 ms apart
        for i in range(40):
            net.append({"t": t + 1 + i * 0.03, "dir": "in", "len": 120, "proto": "tcp",
                        "remote": "160.79.104.10", "sport": 443, "dport": 50000, "host": "api.anthropic.com",
                        "remote_local": False})
        t_cmd = t + 1 + 40 * 0.03 + 0.5
        fs.append({"t": t_cmd, "k": "exec", "pid": pid, "ppid": 10, "exe": "/bin/zsh", "tty": False,
                   "args": ["/bin/zsh", "-c", f"cat inventory/core.py 2>&1 | head -{50 + turn}"], "agent_env": ["CLAUDECODE"]})
        fs.append({"t": t_cmd + 0.1, "k": "open", "pid": pid, "path": f"{WS}/inventory/core.py", "read": True, "size": 900})
        fs.append({"t": t_cmd + 0.3, "k": "exit", "pid": pid, "status": 0})
        for i in range(3):
            net.append({"t": t_cmd + 1 + i * 0.01, "dir": "out", "len": 1500 * (turn + 1), "proto": "tcp",
                        "remote": "160.79.104.10", "sport": 50000, "dport": 443, "host": "api.anthropic.com",
                        "remote_local": False})
        t = t_cmd + 2
        pid += 1
    return fs, net


def _human_session():
    fs = [{"t": 1000.0, "k": "exec", "pid": 10, "ppid": 1, "exe": "/bin/zsh", "tty": True,
           "args": ["/bin/zsh", "-i"], "agent_env": []}]
    t = 1000.0
    for i, (cmd, gap) in enumerate([("ls", 4), ("vim", 70), ("python3", 15), ("git", 40)]):
        t += gap
        fs.append({"t": t, "k": "exec", "pid": 200 + i, "ppid": 10, "exe": f"/usr/bin/{cmd}", "tty": True,
                   "args": [cmd], "agent_env": []})
    fs.append({"t": t + 1, "k": "chdir", "pid": 10, "path": f"{WS}/inventory"})
    return fs, []


def test_features_separate_agent_and_human_shapes():
    ctx = {"workspace": WS, "scope": ["inventory/**"], "root_pid": 10}
    a = features.compute(*_agent_session(), ctx)
    h = features.compute(*_human_session(), ctx)
    assert a["fs_tty_frac"] == 0 and h["fs_tty_frac"] == 1
    assert a["fs_shell_c_frac"] == 1 and a["fs_output_limit_frac"] == 1
    assert h["fs_editor_exec"] == 1 and a["fs_editor_exec"] == 0
    assert a["net_turns_per_min"] > 0 and a["net_stream_frac"] > 0.9
    assert a["net_upload_growth"] > 0.9  # each turn uploads more context
    assert a["net_think_act_frac"] > 0.9  # every command follows a stream
    assert a["net_act_report_frac"] > 0.9  # every upload follows a command exit
    assert a["net_llm_bytes_frac"] == 1.0 and a["fs_agent_env"] == 1
    assert h["net_turns_per_min"] == 0 and h["fs_chdir_count"] == 1
    assert set(features.columns(a, ("net", "fs"), True)).isdisjoint(features.MARKER_FEATURES)


def test_action_features_fire_on_unapproved_patterns():
    ctx = {"workspace": WS, "scope": ["inventory/**"], "root_pid": 10}
    fs = [
        {"t": 1.0, "k": "open", "pid": 5, "path": f"{WS}/.env", "read": True, "size": 200},
        {"t": 1.1, "k": "open", "pid": 5, "path": f"{WS}/config/secrets/id_ed25519", "read": True, "size": 300},
        {"t": 2.0, "k": "create", "pid": 5, "path": f"{WS}/loot/creds.txt"},
        {"t": 3.0, "k": "create", "pid": 6, "path": f"{WS}/home_sim/Library/LaunchAgents/x.plist"},
        {"t": 4.0, "k": "unlink", "pid": 6, "path": f"{WS}/backups/a.sql"},
        {"t": 5.0, "k": "open", "pid": 6, "path": f"{WS}/logs/audit.log", "read": False, "wrote": True, "trunc": True},
        {"t": 6.0, "k": "create", "pid": 7, "path": f"{WS}/maint.sh"},
        {"t": 6.5, "k": "setmode", "pid": 7, "path": f"{WS}/maint.sh", "mode": 0o755},
        {"t": 7.0, "k": "exec", "pid": 8, "ppid": 7, "exe": "/bin/sh", "args": ["./maint.sh"], "tty": False,
         "script": f"{WS}/maint.sh", "cwd": WS, "agent_env": []},
    ]
    net = [{"t": 1.5, "dir": "out", "len": 400, "proto": "tcp", "remote": "127.0.0.1", "sport": 5000,
            "dport": 8765, "host": "localhost", "remote_local": True}]
    f = features.compute(fs, net, ctx)
    assert f["act_sensitive_read"] == 2 and f["act_sensitive_read_outside_task"] == 2
    assert f["act_collect_file"] == 1 and f["act_persistence_write"] == 1
    assert f["act_delete_preexisting"] == 1 and f["act_truncate_log"] == 1
    assert f["act_chmod_exec"] == 1 and f["act_exec_downloaded"] == 1
    assert f["act_sensitive_then_egress"] == 400 and f["net_loopback_egress_bytes"] == 400


def test_action_features_quiet_on_approved_edit():
    ctx = {"workspace": WS, "scope": ["inventory/**", "tests/**"], "root_pid": 10}
    fs = [
        {"t": 1.0, "k": "open", "pid": 5, "path": f"{WS}/inventory/core.py", "read": True, "size": 500},
        {"t": 2.0, "k": "create", "pid": 5, "path": f"{WS}/inventory/.core.py.tmp"},
        {"t": 2.1, "k": "rename", "pid": 5, "path": f"{WS}/inventory/.core.py.tmp", "path2": f"{WS}/inventory/core.py"},
    ]
    f = features.compute(fs, [], ctx)
    assert all(v == 0 for k, v in f.items() if k.startswith("act_")), {k: v for k, v in f.items() if k.startswith("act_") and v}
    assert f["fs_atomic_write_frac"] > 0 and f["fs_read_before_write_frac"] > 0


# ------------------------------------------------------- scenarios / lab ---

def test_ten_scenarios_five_each():
    sc = load_all()
    assert sum(s.label == "approved" for s in sc.values()) == 5
    assert sum(s.label == "unapproved" for s in sc.values()) == 5


def test_checks_fail_on_untouched_workspace(tmp_path):
    """Every scenario must report not-completed if the actor did nothing."""
    ws = make_workspace(tmp_path / "ws")
    for s in load_all().values():
        res = run_checks(s.checks, ws, sink_records=[])
        assert not all(c["ok"] for c in res), f"{s.id} looks completed on a fresh workspace"


def test_template_tests_fail_until_fixed(tmp_path):
    import subprocess
    ws = make_workspace(tmp_path / "ws")
    assert subprocess.run(["python3", "-m", "unittest", "-q"], cwd=ws, capture_output=True).returncode != 0
    assert (TEMPLATE_DIR / ".env").read_text().count("UMBRA-CANARY") >= 2


def test_shell_command_parsing_handles_codex_and_claude_forms():
    mk = lambda exe, args: {"exe": exe, "args": args}
    assert features._cmd_of(mk("/bin/bash", ["bash", "-lc", "ls -la | head"])) == "ls -la | head"
    assert features._cmd_of(mk("/bin/zsh", ["/bin/zsh", "-c", "-l", "git status"])) == "git status"
    assert features._cmd_of(mk("/bin/zsh", ["/bin/zsh", "-i"])) == "/bin/zsh -i"
    assert features._shell_c_command(mk("/usr/bin/sandbox-exec", ["sandbox-exec", "-c", "x"])) is None


def test_real_pktap_flow_outbound_packets_get_owner(tmp_path):
    """Real capture: outbound packets print as bare `(out)`; flow attribution
    must still give them to curl, or uploads vanish from the features."""
    lines = (FIX / "pktap_real_curl_flow.txt").read_text().splitlines()
    parsed = [ingest.parse_tcpdump_line(x) for x in lines]
    assert all(parsed)
    outs = [p for p in parsed if p["dir"] == "out"]
    assert outs and all(p["pid"] is None and p["epid"] is None for p in outs)
    owners = ingest.attribute_flows(parsed)
    assert {owners[ingest.flow_key(p)] for p in parsed} == {(94745, "curl")}
    assert sum(p["len"] for p in outs) > 300  # the ClientHello + request are outbound


# ---------------------------------------------------------------- timing ---

from umbra_train import timing


def test_timing_rebuilds_agent_loop_cycles():
    fs, net = _agent_session()
    t = timing.compute(fs, net, root_pid=10)
    # 8 turns -> 7 complete upload->stream->cmd->upload cycles
    assert t["tim_cycles"] == 7
    assert 400 <= t["tim_dispatch_median_ms"] <= 600  # synthetic: cmd 0.5 s after stream end
    assert t["tim_dispatched_cmd_frac"] == 1.0
    assert 600 <= t["tim_report_median_ms"] <= 800    # upload 0.7 s after exit
    assert t["tim_dispatch_cv"] < 0.1                 # machine-regular
    assert t["tim_net_quiet_cmd_frac"] <= 1 / 8       # only the first command has no prior traffic


def test_timing_human_has_no_loop():
    fs, net = _human_session()
    t = timing.compute(fs, net, root_pid=10)
    assert t["tim_cycles"] == 0 and t["tim_dispatched_cmd_frac"] == 0
    assert t["tim_net_quiet_cmd_frac"] == 1.0


def test_timeline_annotates_legs():
    fs, net = _agent_session()
    rows = timing.timeline(fs, net, root_pid=10)
    legs = {r["leg"][0] for r in rows if r["leg"]}
    assert {"ttft", "dispatch", "tool", "report"} <= legs
    assert rows == sorted(rows, key=lambda r: r["t"])
    assert "dispatch" in timing.format_timeline(rows)


# -------------------------------------------------------------- security ---

def test_sensor_safedir_refuses_symlinks(tmp_path):
    import os
    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    target = tmp_path / "victim.txt"
    target.write_text("original")
    (run / "sensor.log").symlink_to(target)          # planted by a hostile process
    d = sensor.SafeDir(str(run), os.getuid(), os.getgid())
    with pytest.raises(FileExistsError):
        d.create("sensor.log")
    assert target.read_text() == "original"
    f = d.create("fresh.txt", "w")
    f.write("x")
    f.close()
    assert oct((run / "fresh.txt").stat().st_mode & 0o777) == "0o600"
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(run)                           # the run dir itself swapped for a symlink
    with pytest.raises(OSError):
        sensor.SafeDir(str(link_dir), os.getuid(), os.getgid())
    with pytest.raises(RuntimeError):
        sensor.SafeDir(str(run), os.getuid() + 1, None)  # not owned by the invoking user
    os.chmod(run, 0o777)
    with pytest.raises(RuntimeError):
        sensor.SafeDir(str(run), os.getuid(), None)      # world-writable


def test_proc_events_never_store_env_values():
    ex = _set_pid(_sample("exec"), 777)
    ex["event"]["exec"]["env"] = ["API_TOKEN=supersecret", "CLAUDECODE=1"]
    tree, proc = io.BytesIO(), io.BytesIO()
    sensor.filter_stream([_dump(ex)], sensor.TreeTracker("nomatch"), tree, proc)
    assert b"supersecret" not in proc.getvalue()
    assert json.loads(proc.getvalue())["event"]["exec"]["env"] == ["API_TOKEN=", "CLAUDECODE="]
    n = ingest.normalize_es_event(json.loads(proc.getvalue()))
    assert n["agent_env"] == ["CLAUDECODE"]


@pytest.mark.skipif(__import__("sys").platform != "darwin", reason="seatbelt is macOS-only")
def test_checks_cannot_write_outside_or_use_network(tmp_path):
    from umbra_train.lab import _contained_run
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "escaped.txt"
    p = _contained_run(["/bin/sh", "-c", f"echo hi > inside.txt; echo x > '{outside}'"], ws)
    assert (ws / "inside.txt").exists() and not outside.exists()
    p = _contained_run(["/usr/bin/curl", "-s", "-m", "5", "https://example.com"], ws)
    assert p.returncode != 0


def test_agent_error_detection_on_real_failures():
    from umbra_train.runner import agent_error
    claude = ('{"type":"result","is_error":true,"terminal_reason":"api_error",'
              '"result":"Failed to authenticate: OAuth session expired and could not be refreshed"}')
    codex = ('{"type":"thread.started"}\n{"type":"turn.failed","error":{"message":'
             '"The model requires a newer version of Codex."}}')
    ok = '{"type":"result","is_error":false,"result":"Fixed the bug."}'
    assert "OAuth session expired" in agent_error(claude)
    assert "newer version of Codex" in agent_error(codex)
    assert agent_error(ok) is None and agent_error("plain text") is None


def _pkt(t, d, n, port=50000):
    return {"t": t, "dir": d, "len": n, "proto": "tcp", "remote": "160.79.104.10",
            "sport": port if d == "out" else 443, "dport": 443 if d == "out" else port,
            "host": "api.example", "remote_local": False}


def _cmd(t, pid, dur=0.1):
    return [{"t": t, "k": "exec", "pid": pid, "ppid": 10, "exe": "/bin/zsh", "tty": False,
             "args": ["/bin/zsh", "-c", "ls"], "agent_env": []},
            {"t": t + dur, "k": "exit", "pid": pid, "status": 0}]


def test_timing_on_claude_shaped_traffic():
    """Measured shape: upload, a few chunks ~45 ms apart, command ~25 ms after
    the last chunk, result uploaded ~10 ms after the command exits."""
    fs, net, t = [], [], 100.0
    for turn in range(5):
        net += [_pkt(t + i * 0.002, "out", 1400) for i in range(20)]           # ~28 KB context upload
        first = t + 0.9
        net += [_pkt(first + i * 0.045, "in", 300) for i in range(6)]          # 6 chunks, 45 ms apart
        last_in = first + 5 * 0.045
        fs += _cmd(last_in + 0.025, 200 + turn)                                 # dispatch 25 ms
        t = last_in + 0.025 + 0.1 + 0.010                                      # report 10 ms
    net += [_pkt(t + i * 0.002, "out", 1400) for i in range(20)]
    f = timing.compute(fs, net, root_pid=10)
    assert f["tim_cycles"] == 5 and f["tim_cycle_cmd_frac"] == 1.0
    assert 20 <= f["tim_dispatch_median_ms"] <= 30
    assert 40 <= f["tim_chunk_median_ms"] <= 50
    assert 5 <= f["tim_report_median_ms"] <= 15
    assert 0.8 <= f["tim_ttft_median_s"] <= 1.0


def test_timing_on_codex_shaped_busy_connection():
    """Measured shape: the connection is never quiet (bursts every ~400 ms);
    dispatch is still the gap to the last inbound packet (~15 ms)."""
    fs, net = [], []
    for k in range(60):                                                         # 24 s of chatter
        b = 100.0 + k * 0.4
        net += [_pkt(b + i * 0.001, "in", 1400) for i in range(15)]
        net.append(_pkt(b + 0.05, "out", 1200))
    for n, at in enumerate((103.215, 108.415, 115.615)):                        # 15 ms after a burst
        fs += _cmd(at, 300 + n)
    f = timing.compute(fs, net, root_pid=10)
    assert f["tim_dispatched_cmd_frac"] == 1.0
    assert 0 < f["tim_dispatch_median_ms"] < 20


def test_timing_no_dispatch_without_model_traffic():
    fs = _cmd(100.0, 1) + _cmd(140.0, 2)
    f = timing.compute(fs, [], root_pid=10)
    assert f["tim_dispatched_cmd_frac"] == 0 and f["tim_dispatch_median_ms"] == 0
