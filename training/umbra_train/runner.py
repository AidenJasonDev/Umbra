"""Run one (actor, scenario) training session end to end.

  1. copy the workspace template into a fresh sandbox (its own git repo)
  2. start the privileged sensor (eslogger + pktap tcpdump) with sudo
  3. launch the actor under a unique marker so the sensor can find its tree
  4. wait for it to finish (or time out), stop the sensor
  5. normalize captures, run the scenario's outcome checks, record everything
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import ingest, tracker
from .config import RUNS_DIR, SANDBOX_ROOT, SCRUB_ENV_PREFIXES, SENSOR_SCRIPT, Actor, LabConfig
from .lab import Sink, looks_refused, make_workspace, run_checks
from .scenarios import Scenario


IS_WINDOWS = os.name == "nt"


class CaptureUnavailable(RuntimeError):
    """The sensor can't start at all; every later run would fail the same way."""


class SudoKeeper:
    """Ask for the sudo password once per batch, then keep the ticket fresh."""

    def __init__(self):
        self._stop = threading.Event()
        self._t = None

    def start(self):
        if IS_WINDOWS:
            from .capture.windows import is_admin
            if not is_admin():
                raise SystemExit("Capture on Windows needs an elevated prompt: open PowerShell with "
                                 "'Run as administrator', or use --no-capture.")
            return self
        if subprocess.run(["sudo", "-n", "-v"], capture_output=True).returncode != 0:
            if not sys.stdin.isatty():
                raise SystemExit("Capture needs sudo (eslogger and tcpdump are root-only). Run this "
                                 "from a terminal so sudo can ask for your password, or use --no-capture.")
            print("Umbra needs sudo for eslogger + tcpdump (asked once per batch).")
            subprocess.run(["sudo", "-v"], check=True)
        # Same way the sensor will call it, so a broken setup fails here, once.
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            raise SystemExit("sudo works interactively but not non-interactively from this "
                             "terminal, so the sensor can't start. Run umbra-train directly in "
                             "Terminal/iTerm (not via a script that detaches it).")

        def loop():
            while not self._stop.wait(45):
                subprocess.run(["sudo", "-n", "-v"], capture_output=True)

        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()
        return self

    def stop(self):
        self._stop.set()


def scrubbed_env(extra: dict | None = None) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(SCRUB_ENV_PREFIXES)}
    env.update(extra or {})
    return env


def build_command(actor: Actor, sc: Scenario, lab: LabConfig) -> list[str]:
    prompt = f"{lab.preamble}\n\n{sc.prompt}" if lab.preamble else sc.prompt
    cmd = [part.replace("{prompt}", prompt).replace("{script}", sc.script) for part in actor.cmd]
    # npm installs `codex`/`claude` as .cmd shims on Windows; resolve to a real path.
    exe = shutil.which(cmd[0])
    if exe is None and not Path(cmd[0]).exists():
        raise FileNotFoundError(f"{actor.name}: '{cmd[0]}' is not on PATH. Install it, or add its "
                                f"folder to PATH (Claude Code's native installer uses ~/.local/bin).")
    if exe and exe.lower().endswith((".cmd", ".bat")):
        # A .cmd shim runs through cmd.exe, which ends the command at the first
        # newline, so a multi-line prompt arrives empty or cut short. Flatten
        # newlines, and refuse characters cmd.exe would still rewrite.
        args = [" ".join(a.split()) if ("\n" in a or "\r" in a) else a for a in cmd[1:]]
        bad = [c for c in '%"^' if any(c in a for a in args)]
        if bad:
            raise ValueError(f"{actor.name}: {exe} is a .cmd shim and the arguments contain "
                             f"{''.join(bad)}, which cmd.exe would rewrite. Install a native .exe.")
        return [exe, *args]
    return [exe or cmd[0], *cmd[1:]]


def start_sensor(run_dir: Path, marker: str, max_seconds: int):
    if IS_WINDOWS:
        from .capture.windows import WindowsSensor
        s = WindowsSensor(run_dir)
        try:
            s.start()
        except (RuntimeError, subprocess.CalledProcessError) as e:
            raise RuntimeError(f"sensor failed to start: {e}") from e
        return s
    p = subprocess.Popen(
        ["sudo", "-n", sys.executable, "-I", str(SENSOR_SCRIPT),
         "--run-dir", str(run_dir), "--marker", marker, "--max-seconds", str(max_seconds)],
        stdout=open(run_dir / "sensor.stdout", "wb"), stderr=subprocess.STDOUT)
    # No start_new_session here: macOS sudo caches the password per terminal
    # session, so a detached `sudo -n` can't see it ("a password is required").
    # eslogger's own process group (set inside sensor.py) is what keeps the
    # actor's events from being muted.
    deadline = time.time() + 20
    while time.time() < deadline:
        if (run_dir / "READY").exists():
            return p
        if (run_dir / "ERROR").exists() or p.poll() is not None:
            break
        time.sleep(0.2)
    err = (run_dir / "ERROR").read_text() if (run_dir / "ERROR").exists() else \
        (run_dir / "sensor.stdout").read_text(errors="replace")
    (run_dir / "STOP").touch()
    raise RuntimeError(f"sensor failed to start: {err.strip()[:800]}")


def stop_sensor(run_dir: Path, p: subprocess.Popen) -> None:
    (run_dir / "STOP").touch()
    try:
        p.wait(timeout=90)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "-n", "kill", "-TERM", str(p.pid)], capture_output=True)


def _kill_tree(p: subprocess.Popen, own_session: bool):
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
        return
    try:
        if own_session:
            os.killpg(p.pid, signal.SIGTERM)
        else:
            p.terminate()
        p.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(p.pid, signal.SIGKILL) if own_session else p.kill()
        except ProcessLookupError:
            pass


def run_one(actor: Actor, sc: Scenario, lab: LabConfig, sink: Sink, rep: int = 1,
            capture: bool = True, timeout_s: int | None = None) -> dict:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{stamp}-{actor.name}-{sc.id.split('_')[0]}-r{rep}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    ws = make_workspace(SANDBOX_ROOT / run_id)
    marker = f"umbra-run-{uuid.uuid4().hex[:12]}"
    timeout_s = timeout_s or sc.timeout_s
    m: dict = {
        "run_id": run_id, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "actor": actor.name, "actor_kind": actor.kind, "is_agent": int(actor.is_agent),
        "scenario": sc.id, "action_label": sc.label, "category": sc.category, "rep": rep,
        "workspace": str(ws), "marker": marker, "scope": sc.scope,
        "captured": 0, "status": "ok", "notes": "",
    }
    sink.current_run = run_id
    sensor = None
    try:
        if capture:
            sensor = start_sensor(run_dir, marker, timeout_s + 120)
            m["captured"] = 1
        cmd = build_command(actor, sc, lab)
        if not IS_WINDOWS:
            # The marker in argv is how the Mac sensor finds the root exec.
            # On Windows the runner hands the sensor the PID directly instead.
            cmd = ["/bin/sh", "-c", 'exec "$@"', marker, *cmd]
        human = actor.kind == "human"
        if human:
            _print_human_brief(sc, ws)
        m["t_start"] = time.time()
        detach = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WINDOWS \
            else {"start_new_session": True}
        p = subprocess.Popen(
            cmd, cwd=ws, env=scrubbed_env(actor.env),
            stdin=None if human else subprocess.DEVNULL,
            stdout=None if human else open(run_dir / "actor.out", "wb"),
            stderr=None if human else open(run_dir / "actor.err", "wb"),
            **({} if human else detach),  # humans keep the terminal (and its TTY)
        )
        m["root_pid"] = p.pid
        try:
            m["exit_code"] = p.wait(timeout=None if human else timeout_s)
        except subprocess.TimeoutExpired:
            _kill_tree(p, own_session=True)
            m["status"], m["exit_code"] = "timeout", None
        m["t_end"] = time.time()
        m["duration_s"] = round(m["t_end"] - m["t_start"], 2)
        time.sleep(2)  # let trailing packets/events land
    except RuntimeError as e:
        m["status"], m["notes"] = "capture_failed", str(e)
        if "t_start" not in m:  # sensor never came up; the actor was not launched
            (run_dir / "manifest.json").write_text(json.dumps(m, indent=2))
            raise CaptureUnavailable(str(e)) from e
    finally:
        win_stats = None
        if sensor is not None:
            if IS_WINDOWS:
                # Stopping also converts ETW -> fs.jsonl/net.jsonl for this tree.
                win_stats = sensor.stop(m.get("root_pid") or 0)
            else:
                stop_sensor(run_dir, sensor)
        sink.current_run = None

    if m["status"] != "capture_failed":
        if m["captured"]:
            stats = win_stats if IS_WINDOWS else ingest.ingest_run(run_dir)
            m["fs_events"] = stats.get("fs_events", 0)
            m["net_packets"] = (stats.get("net") or {}).get("kept", 0)
            m["net_stats"] = stats.get("net")
            _write_timeline(run_dir)
            pids = json.loads((run_dir / "pids.json").read_text()) if (run_dir / "pids.json").exists() else {}
            if not pids.get("root"):
                m["status"] = "capture_failed"
                m["notes"] = "sensor never saw the marked root exec"
        sink_records = sink.for_run(run_id)
        m["sink_requests"] = [{k: r[k] for k in ("method", "path", "bytes")} for r in sink_records]
        checks = run_checks(sc.checks, ws, sink_records)
        m["checks"] = checks
        m["checks_passed"] = sum(c["ok"] for c in checks)
        m["checks_total"] = len(checks)
        transcript = ""
        for name in ("actor.out", "actor.err"):
            if (run_dir / name).exists():
                transcript += (run_dir / name).read_text(errors="replace")[-20000:]
        if m["checks_passed"] == m["checks_total"]:
            m["outcome"] = "completed"
        elif actor.is_agent and looks_refused(transcript):
            m["outcome"] = "refused"
        else:
            m["outcome"] = "not_completed"

    (run_dir / "manifest.json").write_text(json.dumps(m, indent=2))
    tracker.upsert(m)
    return m


def _write_timeline(run_dir: Path) -> None:
    from . import timing
    pids = json.loads((run_dir / "pids.json").read_text()) if (run_dir / "pids.json").exists() else {}
    fs = ingest.load_jsonl(run_dir / "fs.jsonl")
    net = ingest.load_jsonl(run_dir / "net.jsonl")
    rows = timing.timeline(fs, net, pids.get("root"))
    (run_dir / "timeline.json").write_text(json.dumps(
        {"timing": timing.compute(fs, net, pids.get("root")), "events": rows}, indent=1))


def _print_human_brief(sc: Scenario, ws: Path):
    bar = "=" * 72
    print(f"\n{bar}\nUMBRA HUMAN RUN: {sc.title}  [{sc.id}]\n{bar}")
    print(sc.prompt)
    print(f"\nYou are in a fresh sandbox: {ws}")
    print("Work as you normally would, in THIS shell. Terminal editors (vim, nano) are tracked;")
    print("GUI apps launched from Finder/Dock are not part of this session's process tree.")
    print("Type `exit` when you're done.\n" + bar + "\n")
