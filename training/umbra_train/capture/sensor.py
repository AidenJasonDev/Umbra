#!/usr/bin/env python3
"""Umbra privileged sensor: eslogger + pktap tcpdump for one training run.

Runs as root (eslogger and tcpdump both need it). Uses the standard library only,
because the runner starts it as `sudo python3 -I sensor.py ...` and `-I` keeps the
package path off sys.path.

What it writes into --run-dir:
  fs_raw.jsonl    eslogger events from the tracked process tree only
  proc_all.jsonl  every exec/fork/exit on the machine (small; lets us rebuild
                  process trees later without knowing the root in advance)
  net.pcapng      every packet on every interface, tagged per packet with the
                  owning process (pktap)
  pids.json       the tracked pids and the root
  sensor.log      what the sensor did, including any eslogger/tcpdump errors
  READY / ERROR   handshake files the runner waits on

Tracking: the runner launches the actor as
    /bin/sh -c 'exec "$@"' <marker> <actor command...>
so the first exec whose argv contains <marker> is the session root. Every fork
from a tracked pid is tracked too. Raw eslogger output is ~96% `write` events
from the whole system, so filtering happens on raw bytes before any JSON
parsing, and only tracked-pid lines are ever decoded.

The sensor stops when <run-dir>/STOP appears (the unprivileged runner can create
that file, so it never needs to kill a root process), or on SIGTERM/SIGINT.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

ES_EVENTS = [
    "exec", "fork", "exit",
    "open", "close", "create", "write", "rename", "unlink", "truncate",
    "link", "setmode", "chdir",
    "btm_launch_item_add", "sudo", "su", "setuid",
]
PROC_EVENTS = {"exec", "fork", "exit"}

_EVENT_KEY = re.compile(rb'"event":\{"([a-z_]+)"')
_PID_IN_TOKEN = re.compile(rb'"pid":(\d+)')


def sniff_event_key(line: bytes) -> str | None:
    m = _EVENT_KEY.search(line)
    return m.group(1).decode() if m else None


def sniff_process_pid(line: bytes) -> int | None:
    """Return the acting process's pid without decoding the JSON.

    eslogger emits dict keys in random order, but the top-level "process"
    object is contiguous and contains exactly one key spelled "audit_token"
    (the others are "parent_audit_token" and "responsible_audit_token", which
    don't start with a quote right before "audit_token").
    """
    p = line.find(b'"process":{')
    if p < 0:
        return None
    a = line.find(b'"audit_token":{', p)
    if a < 0:
        return None
    end = line.find(b"}", a)
    m = _PID_IN_TOKEN.search(line, a, end)
    return int(m.group(1)) if m else None


class TreeTracker:
    """Follows one actor's process tree through exec/fork/exit events."""

    def __init__(self, marker: str):
        self.marker = marker
        self.root: int | None = None
        self.live: set[int] = set()
        self.ever: set[int] = set()
        self.execs: list[dict] = []

    def on_proc_event(self, key: str, ev: dict) -> bool:
        """Update the tree. Return True if this event belongs to the tree."""
        pid = ev["process"]["audit_token"]["pid"]
        body = ev["event"][key]
        if key == "exec":
            args = body.get("args") or []
            if self.root is None and any(self.marker in a for a in args):
                self.root = pid
                self.live.add(pid)
                self.ever.add(pid)
            if pid in self.live:
                self.execs.append({
                    "pid": pid,
                    "ppid": ev["process"].get("ppid"),
                    "time": ev.get("time"),
                    "args": args[:20],
                })
                return True
            return False
        if key == "fork":
            if pid in self.live:
                child = body["child"]["audit_token"]["pid"]
                self.live.add(child)
                self.ever.add(child)
                return True
            return False
        if key == "exit":
            if pid in self.live:
                self.live.discard(pid)
                return True
            return False
        return False

    def is_tracked(self, pid: int | None) -> bool:
        return pid is not None and pid in self.live

    def summary(self) -> dict:
        return {"root": self.root, "pids": sorted(self.ever), "n_execs": len(self.execs)}


def filter_stream(lines, tracker: TreeTracker, out_tree, out_proc) -> dict:
    """Core filter loop, separated from I/O so tests can run it on fixtures."""
    stats = {"lines": 0, "kept": 0, "proc": 0, "bad": 0}
    for line in lines:
        stats["lines"] += 1
        key = sniff_event_key(line)
        if key is None:
            stats["bad"] += 1
            continue
        if key in PROC_EVENTS:
            try:
                ev = json.loads(line)
            except ValueError:
                stats["bad"] += 1
                continue
            stats["proc"] += 1
            if out_proc is not None:
                out_proc.write(line if line.endswith(b"\n") else line + b"\n")
            if tracker.on_proc_event(key, ev):
                out_tree.write(line if line.endswith(b"\n") else line + b"\n")
                stats["kept"] += 1
            continue
        if tracker.is_tracked(sniff_process_pid(line)):
            out_tree.write(line if line.endswith(b"\n") else line + b"\n")
            stats["kept"] += 1
    return stats


class Sensor:
    def __init__(self, args):
        self.a = args
        self.run_dir = os.path.abspath(args.run_dir)
        self.log_f = open(os.path.join(self.run_dir, "sensor.log"), "a", buffering=1)
        self.tracker = TreeTracker(args.marker)
        self.es_proc = None
        self.tcp_proc = None
        self.es_thread = None
        self.es_stats: dict = {}
        self.stopping = threading.Event()

    def log(self, msg: str):
        self.log_f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")

    def path(self, name: str) -> str:
        return os.path.join(self.run_dir, name)

    def start_eslogger(self):
        self.es_proc = subprocess.Popen(
            ["/usr/bin/eslogger", *ES_EVENTS],
            stdout=subprocess.PIPE,
            stderr=open(self.path("eslogger.stderr"), "wb"),
            # eslogger silently drops events from every process in its own
            # process group (see `man eslogger`). Give it a group of its own,
            # or it mutes the sensor, the runner, and anything they launch.
            start_new_session=True,
        )

        def pump():
            with open(self.path("fs_raw.jsonl"), "wb") as tree_f, \
                    open(self.path("proc_all.jsonl"), "wb") as proc_f:
                self.es_stats = filter_stream(iter(self.es_proc.stdout.readline, b""),
                                              self.tracker, tree_f, proc_f)

        self.es_thread = threading.Thread(target=pump, daemon=True)
        self.es_thread.start()
        time.sleep(1.5)
        if self.es_proc.poll() is not None:
            err = open(self.path("eslogger.stderr"), "rb").read().decode(errors="replace")
            raise RuntimeError(
                "eslogger exited immediately. It needs root, and the app that "
                "launched it (Terminal, iTerm, VS Code...) needs Full Disk Access "
                f"in System Settings > Privacy & Security.\n{err.strip()}")
        self.log("eslogger running")

    def start_tcpdump(self):
        # pktap,all = every interface incl. loopback; writes pcapng with
        # per-packet process name/pid. 1600-byte snaplen keeps TLS ClientHello
        # (SNI, JA4) and DNS while dropping payload bulk. mDNS is just noise.
        self.tcp_proc = subprocess.Popen(
            ["/usr/sbin/tcpdump", "-i", "pktap,all", "-s", "1600", "-U", "-n",
             "-w", self.path("net.pcapng"), "not (udp port 5353)"],
            stdout=subprocess.DEVNULL,
            stderr=open(self.path("tcpdump.stderr"), "wb"),
            start_new_session=True,
        )
        time.sleep(1.0)
        if self.tcp_proc.poll() is not None:
            err = open(self.path("tcpdump.stderr"), "rb").read().decode(errors="replace")
            raise RuntimeError(f"tcpdump exited immediately:\n{err.strip()}")
        self.log("tcpdump running")

    def stop(self):
        if self.stopping.is_set():
            return
        self.stopping.set()
        if self.tcp_proc and self.tcp_proc.poll() is None:
            self.tcp_proc.send_signal(signal.SIGINT)  # SIGINT flushes the pcapng cleanly
            try:
                self.tcp_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.tcp_proc.kill()
        if self.es_proc and self.es_proc.poll() is None:
            self.es_proc.terminate()
            try:
                self.es_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.es_proc.kill()
        if self.es_thread:
            self.es_thread.join(timeout=30)
        summary = self.tracker.summary()
        summary["eslogger_stats"] = self.es_stats
        with open(self.path("pids.json"), "w") as f:
            json.dump(summary, f, indent=2)
        self.log(f"stopped: {json.dumps(summary)[:400]}")
        self.chown_outputs()

    def chown_outputs(self):
        uid, gid = self.a.owner_uid, self.a.owner_gid
        if uid is None:
            return
        for name in os.listdir(self.run_dir):
            try:
                os.chown(self.path(name), uid, gid)
            except OSError:
                pass

    def run(self):
        signal.signal(signal.SIGTERM, lambda *_: self.stopping.set())
        signal.signal(signal.SIGINT, lambda *_: self.stopping.set())
        try:
            if not self.a.no_fs:
                self.start_eslogger()
            if not self.a.no_net:
                self.start_tcpdump()
        except Exception as e:  # noqa: BLE001 - report any startup failure to the runner
            with open(self.path("ERROR"), "w") as f:
                f.write(str(e))
            self.log(f"ERROR {e}")
            self.stop()
            return 2
        open(self.path("READY"), "w").close()
        self.chown_outputs()
        stop_file = self.path("STOP")
        deadline = time.time() + self.a.max_seconds
        while not self.stopping.is_set():
            if os.path.exists(stop_file) or time.time() > deadline:
                break
            if self.es_proc and self.es_proc.poll() is not None:
                self.log("eslogger died early")
                break
            time.sleep(0.2)
        self.stop()
        return 0


def doctor(run_dir: str) -> int:
    """Self-test as root: can we see a marked exec in eslogger and attribute a
    packet to a pid with pktap? Prints a short report and leaves sample output
    in run_dir so parsers can be checked against real lines."""
    os.makedirs(run_dir, exist_ok=True)
    ns = argparse.Namespace(run_dir=run_dir, marker="umbra-doctor-marker", no_fs=False,
                            no_net=False, max_seconds=30,
                            owner_uid=_env_int("SUDO_UID"), owner_gid=_env_int("SUDO_GID"))
    s = Sensor(ns)
    ok = True
    try:
        s.start_eslogger()
        s.start_tcpdump()
    except RuntimeError as e:
        print(f"FAIL  {e}")
        s.stop()
        return 2
    subprocess.run(["/bin/sh", "-c", 'exec "$@"', "umbra-doctor-marker",
                    "/usr/bin/curl", "-s", "-o", "/dev/null", "-m", "8",
                    "https://example.com/"])
    time.sleep(2)
    s.stop()
    summ = s.tracker.summary()
    if summ["root"]:
        print(f"OK    eslogger saw the marked process (pid {summ['root']}), "
              f"tracked {len(summ['pids'])} pid(s), filter kept {s.es_stats.get('kept')} "
              f"of {s.es_stats.get('lines')} lines")
    else:
        ok = False
        print(f"FAIL  eslogger ran but never saw the marked exec. Stats: {s.es_stats}")
    pcap = os.path.join(run_dir, "net.pcapng")
    out = subprocess.run(["/usr/sbin/tcpdump", "-n", "-tt", "-q", "-k", "NPD", "-r", pcap],
                         capture_output=True, text=True).stdout.splitlines()
    with open(os.path.join(run_dir, "tcpdump_sample.txt"), "w") as f:
        f.write("\n".join(out[:400]))
    curl_lines = [ln for ln in out if "curl" in ln]
    if curl_lines:
        print(f"OK    pktap attributed {len(curl_lines)} packet(s) to curl, e.g.\n      {curl_lines[0][:160]}")
    else:
        ok = False
        print(f"FAIL  no packets attributed to curl ({len(out)} packets total). "
              f"First line: {out[0][:160] if out else '(none)'}")
    s.chown_outputs()
    return 0 if ok else 1


def _env_int(name):
    v = os.environ.get(name)
    return int(v) if v and v.isdigit() else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--marker", default="")
    ap.add_argument("--no-fs", action="store_true")
    ap.add_argument("--no-net", action="store_true")
    ap.add_argument("--max-seconds", type=int, default=1800)
    ap.add_argument("--doctor", action="store_true")
    ap.add_argument("--owner-uid", type=int, default=_env_int("SUDO_UID"))
    ap.add_argument("--owner-gid", type=int, default=_env_int("SUDO_GID"))
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("sensor must run as root (the runner starts it with sudo)", file=sys.stderr)
        return 2
    if a.doctor:
        return doctor(a.run_dir)
    if not a.marker:
        ap.error("--marker is required")
    return Sensor(a).run()


if __name__ == "__main__":
    sys.exit(main())
