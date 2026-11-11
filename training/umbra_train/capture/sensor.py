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
            if key == "exec":
                # Env values can hold other programs' tokens and passwords. Keep
                # only the variable names (the agent-env features need nothing
                # more) and never write a value to disk.
                body = ev["event"]["exec"]
                body["env"] = [e.split("=", 1)[0] + "=" for e in (body.get("env") or [])]
                line = json.dumps(ev, separators=(",", ":")).encode()
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


class SafeDir:
    """Root writing into a directory the (unprivileged) user owns.

    Anything running as that user, including the agent under test, could plant
    symlinks there to trick root into writing to or chowning system files.
    So the directory is opened O_NOFOLLOW and must be owned by the invoking
    user and not group- or world-writable. Every file is created
    O_CREAT|O_EXCL|O_NOFOLLOW relative to that directory fd, mode 0600. It's
    handed to the user with fchown on the open fd, never chown by path.
    """

    def __init__(self, path: str, uid: int | None, gid: int | None):
        self.path = os.path.abspath(path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        st = os.fstat(self.fd)
        if uid is not None and st.st_uid != uid:
            raise RuntimeError(f"run dir {self.path} is not owned by uid {uid}")
        if st.st_mode & 0o022:
            raise RuntimeError(f"run dir {self.path} is group/world-writable")
        self.uid, self.gid = uid, gid

    def create(self, name: str, mode: str = "wb", buffering: int = -1):
        if "/" in name:
            raise ValueError(name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=self.fd)
        if self.uid is not None:
            os.fchown(fd, self.uid, self.gid if self.gid is not None else -1)
        return os.fdopen(fd, mode, buffering=buffering)

    def open_read(self, name: str):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        return os.fdopen(fd, "rb")

    def exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False


class Sensor:
    def __init__(self, args):
        self.a = args
        self.dir = SafeDir(args.run_dir, args.owner_uid, args.owner_gid)
        self.run_dir = self.dir.path
        self.log_f = self.dir.create("sensor.log", "w", buffering=1)
        self.tracker = TreeTracker(args.marker)
        self.es_proc = None
        self.tcp_proc = None
        self.es_thread = None
        self.es_stats: dict = {}
        self.stop_requested = threading.Event()  # set by signals / STOP file
        self.stopping = threading.Event()        # guard: stop() runs once

    def log(self, msg: str):
        self.log_f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")

    def path(self, name: str) -> str:
        return os.path.join(self.run_dir, name)

    def start_eslogger(self):
        self.es_proc = subprocess.Popen(
            ["/usr/bin/eslogger", *ES_EVENTS],
            stdout=subprocess.PIPE,
            stderr=self.dir.create("eslogger.stderr"),
            # eslogger silently drops events from every process in its own
            # process group (see `man eslogger`). Give it a group of its own,
            # or it mutes the sensor, the runner, and anything they launch.
            start_new_session=True,
        )

        def pump():
            with self.dir.create("fs_raw.jsonl") as tree_f, \
                    self.dir.create("proc_all.jsonl") as proc_f:
                self.es_stats = filter_stream(iter(self.es_proc.stdout.readline, b""),
                                              self.tracker, tree_f, proc_f)

        self.es_thread = threading.Thread(target=pump, daemon=True)
        self.es_thread.start()
        time.sleep(1.5)
        if self.es_proc.poll() is not None:
            err = self.dir.open_read("eslogger.stderr").read().decode(errors="replace")
            raise RuntimeError(
                "eslogger exited immediately. It needs root, and the app that "
                "launched it (Terminal, iTerm, VS Code...) needs Full Disk Access "
                f"in System Settings > Privacy & Security.\n{err.strip()}")
        self.log("eslogger running")

    def start_tcpdump(self):
        # pktap,all = every interface incl. loopback; writes pcapng with
        # per-packet process name/pid. 1600-byte snaplen keeps TLS ClientHello
        # (SNI, JA4) and DNS while dropping payload bulk. mDNS is just noise.
        # `-w -`: tcpdump writes to a file we created safely, never a path of its own.
        self.tcp_proc = subprocess.Popen(
            ["/usr/sbin/tcpdump", "-i", "pktap,all", "-s", "1600", "-U", "-n",
             "-w", "-", "not (udp port 5353)"],
            stdout=self.dir.create("net.pcapng"),
            stderr=self.dir.create("tcpdump.stderr"),
            # Deliberately NOT a new session (unlike eslogger, which needs one
            # to avoid muting): if the sensor is killed, Ctrl-C still reaches
            # tcpdump, so a root capture is never left running.
        )
        time.sleep(1.0)
        if self.tcp_proc.poll() is not None:
            err = self.dir.open_read("tcpdump.stderr").read().decode(errors="replace")
            raise RuntimeError(f"tcpdump exited immediately:\n{err.strip()}")
        self.log("tcpdump running")

    def drain(self, timeout: float = 15.0):
        """eslogger's output can lag seconds behind on a busy machine. Before
        stopping, wait until the root has been seen *and* has exited (plus a
        short grace for its children), or until timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.es_proc is None or self.es_proc.poll() is not None:
                return
            t = self.tracker
            if t.root is not None and t.root not in t.live:
                time.sleep(1.0)
                return
            time.sleep(0.1)
        self.log(f"drain timed out (root={self.tracker.root})")

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
        with self.dir.create("pids.json", "w") as f:
            json.dump(summary, f, indent=2)
        self.log(f"stopped: {json.dumps(summary)[:400]}")

    def _kill_children(self):
        for p in (self.tcp_proc, self.es_proc):
            if p and p.poll() is None:
                p.kill()

    def run(self):
        import atexit
        atexit.register(self._kill_children)  # never leave root capture running
        # Signals only *request* a stop. (They used to set the same flag stop()
        # checks to run once, so Ctrl-C made stop() return without killing
        # tcpdump, leaving a root capture running.)
        signal.signal(signal.SIGTERM, lambda *_: self.stop_requested.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_requested.set())
        try:
            if not self.a.no_fs:
                self.start_eslogger()
            if not self.a.no_net:
                self.start_tcpdump()
        except Exception as e:  # noqa: BLE001 - report any startup failure to the runner
            with self.dir.create("ERROR", "w") as f:
                f.write(str(e))
            self.log(f"ERROR {e}")
            self.stop()
            return 2
        self.dir.create("READY").close()
        deadline = time.time() + self.a.max_seconds
        while not self.stop_requested.is_set():
            if self.dir.exists("STOP") or time.time() > deadline:
                self.drain()
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
    ns = argparse.Namespace(run_dir=run_dir, marker="umbra-doctor-marker", no_fs=False,
                            no_net=False, max_seconds=30,
                            owner_uid=_env_int("SUDO_UID"), owner_gid=_env_int("SUDO_GID"))
    try:
        s = Sensor(ns)
    except (RuntimeError, OSError) as e:
        print(f"FAIL  unsafe run directory: {e}")
        return 2
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
    s.drain()
    s.stop()
    summ = s.tracker.summary()
    if summ["root"]:
        print(f"OK    eslogger saw the marked process (pid {summ['root']}), "
              f"tracked {len(summ['pids'])} pid(s), filter kept {s.es_stats.get('kept')} "
              f"of {s.es_stats.get('lines')} lines")
    else:
        ok = False
        print(f"FAIL  eslogger ran but never saw the marked exec. Stats: {s.es_stats}")
    with s.dir.open_read("net.pcapng") as pcap:
        out = subprocess.run(["/usr/sbin/tcpdump", "-n", "-tt", "-q", "-k", "NPD", "-r", "-"],
                             stdin=pcap, capture_output=True, text=True).stdout.splitlines()
    with s.dir.create("tcpdump_sample.txt", "w") as f:
        f.write("\n".join(out[:400]))
    curl_lines = [ln for ln in out if "curl" in ln]
    if curl_lines:
        print(f"OK    pktap attributed {len(curl_lines)} packet(s) to curl, e.g.\n      {curl_lines[0][:160]}")
    else:
        ok = False
        print(f"FAIL  no packets attributed to curl ({len(out)} packets total). "
              f"First line: {out[0][:160] if out else '(none)'}")
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
    os.umask(0o077)  # anything root creates is private to its owner
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
