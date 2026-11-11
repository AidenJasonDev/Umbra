"""Umbra Windows sensor: the Windows counterpart of sensor.py (eslogger + pktap).

Uses only tools that ship with Windows 10/11, plus Python's standard library:

  Mac                          Windows (this file)
  ---------------------------  -----------------------------------------------
  eslogger exec/fork/exit      ETW Microsoft-Windows-Kernel-Process (start/stop)
                               + Security event 4688 for full command lines
  eslogger open/close/write/   ETW Microsoft-Windows-Kernel-File
    create/rename/unlink         (create, read, write, delete, rename, new file)
  pktap per-packet process     ETW Microsoft-Windows-Kernel-Network: TCP/UDP
                                 send/recv with PID, size and both endpoints
                                 (every send names its process, so no flow
                                 attribution trick is needed)
  DNS answers via tshark       ETW Microsoft-Windows-DNS-Client 3008, which
                                 also names the requesting process
  pcapng for SNI/JA4           pktmon (built in) -> pcapng -> the same tshark code
  sudo                         an elevated (Administrator) prompt

ETW is recorded to an .etl file with `logman`, converted after the run with
`tracerpt` (XML), and normalized into exactly the fs.jsonl / net.jsonl
schema that ingest.py produces on the Mac. Everything downstream (features,
the timing module, experiments, the report) runs unchanged.

Tracking: the runner launches the actor itself and writes its PID to
<run-dir>/root.pid. ETW records the whole machine to disk, so the process tree
is rebuilt afterwards from ProcessStart parent links and nothing is lost to
a race.

STATUS: written against the documented ETW manifests but NOT yet run on
Windows hardware. Run `umbra-train doctor` on the Windows box first. It saves
raw samples so the field names can be checked against the real output.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

SESSION = "UmbraSensor"

PROV_PROCESS = "Microsoft-Windows-Kernel-Process"
PROV_FILE = "Microsoft-Windows-Kernel-File"
PROV_NET = "Microsoft-Windows-Kernel-Network"
PROV_DNS = "Microsoft-Windows-DNS-Client"

# provider, keywords, level. Keywords from the providers' manifests
# (`logman query providers <name>` lists them on the box).
PROVIDERS = [
    (PROV_PROCESS, 0x10, 5),          # WINEVENT_KEYWORD_PROCESS
    # FILENAME|FILEIO|CREATE|READ|WRITE|DELETE_PATH|RENAME_SETLINK_PATH|CREATE_NEW_FILE
    (PROV_FILE, 0x10 | 0x20 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000, 5),
    (PROV_NET, 0x10 | 0x20, 5),       # KERNEL_NETWORK_KEYWORD_IPV4 | IPV6
    (PROV_DNS, 0x8000000000000000, 5),
]

# Event IDs per provider (manifest-based providers).
PROC_START, PROC_STOP = 1, 2
FILE_CREATE, FILE_CLOSE, FILE_READ, FILE_WRITE = 12, 14, 15, 16
FILE_DELETE_PATH, FILE_RENAME_PATH, FILE_CREATE_NEW = 26, 27, 30
NET_SEND = {10, 26, 42, 58}           # TCPv4, TCPv6, UDPv4, UDPv6 send
NET_RECV = {11, 27, 43, 59}           # ... receive
NET_UDP = {42, 43, 58, 59}
DNS_QUERY_DONE = 3008

DISP_OVERWRITE = {4, 5}               # FILE_OVERWRITE, FILE_OVERWRITE_IF -> truncation
DISP_CREATE = {2}                     # FILE_CREATE


# ------------------------------------------------------------ recording ---

def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def is_admin() -> bool:
    if os.name != "nt":
        return False
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def enable_cmdline_auditing() -> None:
    """Security 4688 with command lines. Built in, off by default."""
    _run(["auditpol", "/set", "/subcategory:Process Creation", "/success:enable"], check=False)
    _run(["reg", "add", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
          "/v", "ProcessCreationIncludeCmdLine_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"], check=False)


def start_etw(etl: Path) -> None:
    _run(["logman", "stop", SESSION, "-ets"], check=False)  # clear a stale session
    pf = etl.with_suffix(".providers.txt")
    pf.write_text("".join(f'"{name}" 0x{kw:x} {lvl}\n' for name, kw, lvl in PROVIDERS))
    _run(["logman", "start", SESSION, "-ets", "-o", str(etl), "-pf", str(pf),
          "-bs", "1024", "-nb", "64", "256", "-mode", "Sequential"])


def stop_etw() -> None:
    _run(["logman", "stop", SESSION, "-ets"], check=False)


def start_pktmon(etl: Path) -> bool:
    if not shutil.which("pktmon"):
        return False
    _run(["pktmon", "stop"], check=False)
    _run(["pktmon", "filter", "remove"], check=False)
    p = _run(["pktmon", "start", "--capture", "--pkt-size", "1600", "--file-name", str(etl)], check=False)
    return p.returncode == 0


def stop_pktmon(etl: Path, pcap: Path) -> None:
    _run(["pktmon", "stop"], check=False)
    if etl.exists():
        _run(["pktmon", "etl2pcap", str(etl), "--out", str(pcap)], check=False)


def export_4688(since_utc: str, out_xml: Path) -> None:
    q = (f"*[System[(EventID=4688) and TimeCreated[@SystemTime>='{since_utc}']]]")
    # /uni:true -> UTF-16. Without it wevtutil writes the ANSI code page (an em
    # dash in a command line comes out as 0x97 and breaks the UTF-8 XML parse;
    # anything outside that code page becomes '?').
    p = subprocess.run(["wevtutil", "qe", "Security", f"/q:{q}", "/f:xml", "/e:Events", "/uni:true"],
                       capture_output=True)
    text = p.stdout.decode("utf-16", errors="replace").lstrip("﻿") if p.stdout else ""
    out_xml.write_text(text if text.strip() else "<Events/>", encoding="utf-8")


def etl_to_xml(etl: Path, out_xml: Path) -> None:
    _run(["tracerpt", str(etl), "-o", str(out_xml), "-of", "XML", "-y", "-lr"], check=False)


def device_map() -> dict[str, str]:
    r"""\Device\HarddiskVolume3 -> C:  (Kernel-File reports device paths)."""
    out: dict[str, str] = {}
    if os.name != "nt":
        return out
    import ctypes
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
            out[buf.value] = f"{letter}:"
    return out


# --------------------------------------------------------------- parsing ---

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _event_record(ev, pre=None, keep=None) -> dict | None:
    """Header first (provider, id, pid); `pre(provider, pid)` can reject the
    event before its data and timestamp are decoded, which is most of the cost
    when 99% of a system-wide trace belongs to other processes."""
    system = data_el = None
    for child in ev:
        name = _local(child.tag)
        if name == "System":
            system = child
        elif name in ("EventData", "UserData"):
            data_el = child
    if system is None:
        return None
    rec: dict = {"data": {}}
    systime = ""
    for s in system:
        sn = _local(s.tag)
        if sn == "Provider":
            rec["provider"] = s.get("Name")
        elif sn == "EventID":
            rec["id"] = int((s.text or "0").strip())
        elif sn == "TimeCreated":
            systime = s.get("SystemTime") or ""
        elif sn == "Execution":
            rec["pid"] = _int(s.get("ProcessID"))
            rec["tid"] = _int(s.get("ThreadID"))
    if "id" not in rec:
        return None
    if pre is not None and not pre(rec.get("provider"), rec.get("pid")):
        return None
    if data_el is not None:
        for d in data_el.iter():
            if _local(d.tag) == "Data" and d.get("Name"):
                rec["data"][d.get("Name")] = (d.text or "").strip()
    if keep is not None and not keep(rec):
        return None
    rec["t"] = parse_systime(systime)
    return rec


def iter_events_xml(path_or_text, keep=None, pre=None):
    """Stream tracerpt / wevtutil XML as flat dicts:
    {provider, id, t, pid, tid, data: {Name: value}}.
    Streams, so a multi-GB etw.xml (system-wide Kernel-File during a pip
    install) never sits in memory. `pre(provider, pid)` is a cheap header
    filter; `keep(rec)` sees the decoded data (but not yet `t`)."""
    import io
    if isinstance(path_or_text, Path):
        if not path_or_text.exists() or path_or_text.stat().st_size == 0:
            return
        src = open(path_or_text, "rb")
    else:
        if not path_or_text.strip():
            return
        src = io.BytesIO(path_or_text.encode("utf-8"))
    with src:
        # tracerpt/wevtutil never emit a DTD; refuse one so entity expansion
        # (billion laughs) can't happen even if a file is swapped underneath us.
        # A DTD can only sit in the prolog, before the root element.
        head = src.read(65536)
        src.seek(0)
        prolog = re.split(rb"<[A-Za-z]", head, maxsplit=1)[0].upper()
        if b"<!DOCTYPE" in prolog or b"<!ENTITY" in prolog:
            raise ValueError("refusing XML with a DTD/entity declaration")
        root = None
        for kind, el in ET.iterparse(src, events=("start", "end")):
            if kind == "start":
                if root is None:
                    root = el
                continue
            if _local(el.tag) != "Event":
                continue
            rec = _event_record(el, pre, keep)
            el.clear()
            if root is not None:
                root.clear()  # drop finished events so memory stays flat
            if rec is not None:
                yield rec


def parse_events_xml(path_or_text, keep=None, pre=None) -> list[dict]:
    return list(iter_events_xml(path_or_text, keep, pre))


_SYSTIME = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)?$")


def parse_systime(s: str) -> float:
    """SystemTime -> epoch seconds. wevtutil writes UTC ('...06.1234567Z');
    tracerpt writes local time with an offset ('...06.123456700-06:00').
    Fractions go up to 9 digits, more than fromisoformat accepts."""
    if not s:
        return 0.0
    m = _SYSTIME.match(s.strip())
    if not m:
        raise ValueError(f"unrecognized SystemTime: {s!r}")
    base, frac, tz = m.groups()
    tz = "+00:00" if tz in (None, "Z") else tz
    dt = datetime.fromisoformat(base + tz)
    return dt.timestamp() + (float("0." + frac) if frac else 0.0)


def _int(v) -> int | None:
    if v is None or v == "":
        return None
    v = str(v).strip()
    try:
        return int(v, 16) if v.lower().startswith("0x") else int(v)
    except ValueError:
        return None


def norm_path(p: str | None, devmap: dict[str, str]) -> str | None:
    r"""\Device\HarddiskVolume3\Users\x -> C:/Users/x ; C:\a\b -> C:/a/b"""
    if not p:
        return None
    for dev, letter in devmap.items():
        if p.lower().startswith(dev.lower() + "\\"):
            p = letter + p[len(dev):]
            break
    if p.startswith("\\??\\"):
        p = p[4:]
    return p.replace("\\", "/")


def split_cmdline(cmd: str) -> list[str]:
    try:
        parts = shlex.split(cmd, posix=False)
    except ValueError:
        parts = cmd.split()
    return [x[1:-1] if len(x) >= 2 and x[0] == x[-1] == '"' else x for x in parts]


# ------------------------------------------------------------ normalize ---

def build_tree(events: list[dict], root_pid: int) -> set[int]:
    """All pids descended from root_pid, from ProcessStart parent links."""
    children: dict[int, list[int]] = {}
    for e in events:
        if e.get("provider") == PROV_PROCESS and e["id"] == PROC_START:
            pid = _int(e["data"].get("ProcessID"))
            ppid = _int(e["data"].get("ParentProcessID"))
            if pid is not None and ppid is not None:
                children.setdefault(ppid, []).append(pid)
    tree, stack = {root_pid}, [root_pid]
    while stack:
        for c in children.get(stack.pop(), []):
            if c not in tree:
                tree.add(c)
                stack.append(c)
    return tree


def normalize(events: list[dict], sec4688: list[dict], root_pid: int,
              devmap: dict[str, str] | None = None) -> tuple[list[dict], list[dict], set[int]]:
    """ETW + 4688 -> (fs events, packets, tracked pids) in ingest.py's schema."""
    devmap = devmap or {}
    events = sorted(events, key=lambda e: e.get("t", 0))
    tree = build_tree(events, root_pid)

    cmdlines: dict[int, dict] = {}
    for e in sec4688:
        if e["id"] != 4688:
            continue
        d = e["data"]
        pid = _int(d.get("NewProcessId"))
        if pid is not None:
            cmdlines[pid] = {"cmd": d.get("CommandLine") or "", "exe": d.get("NewProcessName"),
                             "elevated": d.get("TokenElevationType", "").endswith("1937")}

    fs: list[dict] = []
    net: list[dict] = []
    fobj: dict[str, dict] = {}         # FileObject -> open record (to attach reads/writes)
    dns: dict[str, str] = {}

    def emit_open(rec):
        if rec and not rec.get("_emitted"):
            rec["_emitted"] = True
            fs.append({k: v for k, v in rec.items() if not k.startswith("_")})

    for e in events:
        prov, eid, d, t = e.get("provider"), e["id"], e["data"], e.get("t", 0.0)
        if prov == PROV_PROCESS:
            pid = _int(d.get("ProcessID"))
            if pid not in tree:
                continue
            if eid == PROC_START:
                c = cmdlines.get(pid, {})
                exe = norm_path(c.get("exe") or d.get("ImageName"), devmap)
                args = split_cmdline(c["cmd"]) if c.get("cmd") else [exe or ""]
                fs.append({"t": t, "k": "fork", "pid": _int(d.get("ParentProcessID")), "child": pid,
                           "ppid": None, "exe": None, "tty": False})
                fs.append({"t": t, "k": "exec", "pid": pid, "ppid": _int(d.get("ParentProcessID")),
                           "exe": exe, "tty": False, "args": args, "cwd": None, "script": None,
                           "agent_env": []})
                if c.get("elevated"):
                    fs.append({"t": t, "k": "setuid", "pid": pid, "ppid": None, "exe": exe, "tty": False})
            elif eid == PROC_STOP:
                fs.append({"t": t, "k": "exit", "pid": pid, "ppid": None, "exe": None, "tty": False,
                           "status": _int(d.get("ExitCode"))})
        elif prov == PROV_FILE:
            pid = e.get("pid")
            if pid not in tree:
                continue
            path = norm_path(d.get("FileName") or d.get("OpenPath"), devmap)
            key = d.get("FileObject") or d.get("FileKey")
            if eid in (FILE_CREATE,):
                opts = _int(d.get("CreateOptions")) or 0
                disp = (opts >> 24) & 0xFF
                rec = {"t": t, "k": "open", "pid": pid, "ppid": None, "exe": None, "tty": False,
                       "path": path, "read": False, "wrote": False, "trunc": disp in DISP_OVERWRITE,
                       "size": 0}
                if key:
                    fobj[key] = rec
                if disp in DISP_CREATE:
                    fs.append({"t": t, "k": "create", "pid": pid, "ppid": None, "exe": None,
                               "tty": False, "path": path})
                if disp in DISP_OVERWRITE:
                    rec["wrote"] = True
                    emit_open(rec)
            elif eid in (FILE_READ, FILE_WRITE):
                rec = fobj.get(key)
                if rec is None:
                    continue
                if eid == FILE_READ:
                    rec["read"] = True
                    rec["size"] = (rec.get("size") or 0) + (_int(d.get("IOSize")) or 0)
                else:
                    if not rec["wrote"]:
                        fs.append({"t": t, "k": "write", "pid": pid, "ppid": None, "exe": None,
                                   "tty": False, "path": rec["path"]})
                    rec["wrote"] = True
            elif eid == FILE_CLOSE:
                rec = fobj.pop(key, None)
                if rec is not None and (rec["read"] or rec["wrote"]):
                    emit_open(rec)
                    if rec["wrote"]:
                        fs.append({"t": t, "k": "close", "pid": pid, "ppid": None, "exe": None,
                                   "tty": False, "path": rec["path"], "wrote": True})
            elif eid == FILE_CREATE_NEW:
                fs.append({"t": t, "k": "create", "pid": pid, "ppid": None, "exe": None,
                           "tty": False, "path": path})
            elif eid == FILE_DELETE_PATH:
                fs.append({"t": t, "k": "unlink", "pid": pid, "ppid": None, "exe": None,
                           "tty": False, "path": path})
            elif eid == FILE_RENAME_PATH:
                dest = norm_path(d.get("FilePath") or d.get("NewFileName"), devmap)
                fs.append({"t": t, "k": "rename", "pid": pid, "ppid": None, "exe": None,
                           "tty": False, "path": path, "path2": dest})
        elif prov == PROV_NET:
            pid = _int(d.get("PID")) or e.get("pid")
            if pid not in tree or (eid not in NET_SEND and eid not in NET_RECV):
                continue
            # Kernel-Network names the connection the same way for both
            # directions: daddr/dport = remote, saddr/sport = local.
            out = eid in NET_SEND
            remote, local = d.get("daddr", ""), d.get("saddr", "")
            rport, lport = _int(d.get("dport")) or 0, _int(d.get("sport")) or 0
            net.append({"t": t, "pid": pid, "proc": None, "eproc": None, "epid": None,
                        "dir": "out" if out else "in", "proto": "udp" if eid in NET_UDP else "tcp",
                        "src": local if out else remote, "sport": lport if out else rport,
                        "dst": remote if out else local, "dport": rport if out else lport,
                        "len": _int(d.get("size")) or 0, "remote": remote})
        elif prov == PROV_DNS and eid == DNS_QUERY_DONE:
            name = d.get("QueryName", "")
            for ip in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F]+", d.get("QueryResults", "")):
                ip = ip.removeprefix("::ffff:")
                dns.setdefault(ip, name)

    for rec in fobj.values():
        if rec["read"] or rec["wrote"]:
            emit_open(rec)
    fs.sort(key=lambda x: x["t"])

    import ipaddress

    def is_local(a: str) -> bool:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local

    for p in net:
        p["remote_local"] = is_local(p["remote"])
        p["host"] = dns.get(p["remote"], "") or ("localhost" if p["remote"] in ("127.0.0.1", "::1") else "")
    return fs, net, tree


def finish_run(run_dir: Path, root_pid: int, devmap: dict[str, str] | None = None) -> dict:
    """Convert a stopped run's captures into fs.jsonl / net.jsonl / pids.json."""
    from .. import ingest  # SNI/JA4 from pktmon pcapng via tshark, same code as the Mac

    etw_xml = run_dir / "etw.xml"
    # Pass 1: process events only (few), to learn the actor's tree.
    # Pass 2: keep only that tree's file/network events, plus DNS for host labels.
    total = 0

    def count_procs(prov, _pid):
        nonlocal total
        total += 1
        return prov == PROV_PROCESS
    procs = parse_events_xml(etw_xml, pre=count_procs)
    tree = build_tree(procs, root_pid)

    def head_in_tree(prov, pid):
        # Kernel-Network's header pid is often System; its real PID is in the data.
        return prov in (PROV_PROCESS, PROV_DNS, PROV_NET) or pid in tree

    def net_in_tree(rec):
        if rec.get("provider") == PROV_NET:
            return (_int(rec["data"].get("PID")) or rec.get("pid")) in tree
        return True
    events = parse_events_xml(etw_xml, keep=net_in_tree, pre=head_in_tree)
    sec = parse_events_xml(run_dir / "sec4688.xml")
    fs, net, tree = normalize(events, sec, root_pid, devmap)
    pcap = run_dir / "net.pcapng"
    if pcap.exists():
        flows, names = ingest.tls_and_dns_maps(pcap)
        for p in net:
            fwd = (p["src"], p["sport"], p["dst"], p["dport"])
            rev = (p["dst"], p["dport"], p["src"], p["sport"])
            sni, ja4 = flows.get(fwd) or flows.get(rev) or ("", "")
            p["host"] = sni or p["host"] or names.get(p["remote"], "")
            if fwd in flows:
                p["ja4"] = ja4
    with open(run_dir / "fs.jsonl", "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in fs)
    with open(run_dir / "net.jsonl", "w") as f:
        f.writelines(json.dumps(p) + "\n" for p in net)
    (run_dir / "pids.json").write_text(json.dumps({"root": root_pid, "pids": sorted(tree)}, indent=2))
    return {"fs_events": len(fs), "net": {"kept": len(net)}, "etw_events": total,
            "cmdlines": sum(1 for e in sec if e["id"] == 4688)}


# --------------------------------------------------------------- session ---

class WindowsSensor:
    """Same contract as sensor.py: READY/ERROR/STOP files in the run dir."""

    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.etl = self.run_dir / "etw.etl"
        self.pkt_etl = self.run_dir / "pktmon.etl"
        self.started_utc = ""
        self.pktmon = False

    def start(self) -> None:
        if not is_admin():
            raise RuntimeError("The Windows sensor needs an elevated prompt (Run as administrator).")
        enable_cmdline_auditing()
        self.started_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        start_etw(self.etl)
        self.pktmon = start_pktmon(self.pkt_etl)
        (self.run_dir / "READY").touch()

    def stop(self, root_pid: int, keep_xml: bool = False) -> dict:
        stop_etw()
        if self.pktmon:
            stop_pktmon(self.pkt_etl, self.run_dir / "net.pcapng")
        etl_to_xml(self.etl, self.run_dir / "etw.xml")
        export_4688(self.started_utc, self.run_dir / "sec4688.xml")
        stats = finish_run(self.run_dir, root_pid, device_map())
        if not keep_xml:
            # etw.xml is ~10x the .etl (GBs for a pip install) and can be
            # regenerated from etw.etl with etl_to_xml, so drop it once ingested.
            (self.run_dir / "etw.xml").unlink(missing_ok=True)
        return stats


def doctor(run_dir: Path) -> int:
    """Windows self-test: one curl.exe under the sensor, then check that its
    process, file and network events and its command line all came through."""
    run_dir.mkdir(parents=True, exist_ok=True)
    s = WindowsSensor(run_dir)
    try:
        s.start()
    except (RuntimeError, subprocess.CalledProcessError) as e:
        print(f"FAIL  sensor start: {e}")
        return 2
    time.sleep(1)
    # Write the body to a real file: `-o NUL` does no file I/O, and DLL loads
    # are paging reads that don't count as opens, so the file check needs this.
    out_file = (run_dir / "doctor_download.html").resolve()
    wall_start = time.time()
    p = subprocess.Popen(["curl.exe", "-s", "-o", str(out_file), "-m", "8", "https://example.com/"])
    p.wait()
    wall_end = time.time()
    time.sleep(2)
    stats = s.stop(p.pid, keep_xml=True)
    fs = [json.loads(x) for x in (run_dir / "fs.jsonl").read_text().splitlines()]
    net = [json.loads(x) for x in (run_dir / "net.jsonl").read_text().splitlines()]
    ok = True

    def report(cond, good, bad):
        nonlocal ok
        print(("OK    " + good) if cond else ("FAIL  " + bad))
        ok &= bool(cond)

    report(any(e["k"] == "exec" for e in fs), f"process events for curl (pid {p.pid})",
           f"no ProcessStart for pid {p.pid}; {stats['etw_events']} ETW events total")
    report(any(e["k"] == "exec" and len(e.get("args") or []) > 1 for e in fs),
           "full command line from Security 4688", "no command line (4688 auditing may need a reboot or GPO)")
    want = out_file.as_posix().lower()
    report(any(e["k"] in ("open", "write", "create") and (e.get("path") or "").lower() == want for e in fs),
           f"file write to {out_file.name} from Kernel-File",
           f"no Kernel-File write for {out_file.name}; {sum(1 for e in fs if e['k'] == 'open')} opens kept")
    # Event times must fall inside the wall-clock span of the curl run
    # (tracerpt's local-time offset once put them hours off and emptied every window).
    times = [e["t"] for e in fs] + [p_["t"] for p_ in net]
    report(bool(times) and all(wall_start - 5 <= t <= wall_end + 5 for t in times),
           "event times match the wall clock",
           f"event times off the wall clock by {min(times or [wall_start]) - wall_start:+.0f}s")
    report(any(p_["dir"] == "out" for p_ in net) and any(p_["dir"] == "in" for p_ in net),
           f"{len(net)} network events with PID, both directions", "no Kernel-Network send/recv for curl")
    report(any(p_.get("host") == "example.com" for p_ in net), "host labelled example.com (DNS/SNI)",
           "host not labelled; check DNS-Client events and tshark")
    print(f"\nRaw samples kept in {run_dir} (etw.xml, sec4688.xml) to check field names.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(doctor(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("umbra-doctor")))
