"""Turn a run's raw captures into compact, normalized event streams.

fs_raw.jsonl (eslogger)  -> fs.jsonl   one dict per filesystem/process event
net.pcapng   (pktap)     -> net.jsonl  one dict per packet from the tracked tree

Normalized fs event keys:
  t      epoch seconds (float)
  k      kind: exec fork exit open close create write rename unlink truncate
         link setmode chdir btm_add sudo su setuid
  pid, ppid, exe, tty (bool)
  args, cwd, script, agent_env  (exec only)
  path, path2                (file events; path2 = rename/link destination)
  read, wrote, trunc, size   (open: fflag bits and file size; close: modified)
  status                     (exit only)

Normalized packet keys:
  t, pid, proc, dir ('out'|'in'), proto, src, sport, dst, dport, len, host,
  ja4 (ClientHello only)
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

AGENT_ENV_PREFIXES = ("CLAUDECODE", "CLAUDE_CODE", "CODEX_", "AI_AGENT", "ANTHROPIC_",
                      "OPENAI_", "CURSOR_", "GEMINI_CLI", "AIDER_")

TSHARK_CANDIDATES = ["tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark",
                     "C:/Program Files/Wireshark/tshark.exe"]


def parse_time(s: str) -> float:
    # "2026-11-06T02:43:59.552532062Z" -> trim nanoseconds to microseconds
    if s.endswith("Z"):
        s = s[:-1]
    if "." in s:
        base, frac = s.split(".", 1)
        s = f"{base}.{frac[:6]}"
    return datetime.fromisoformat(s + "+00:00").timestamp()


def _p(d: dict | None) -> str | None:
    return d.get("path") if isinstance(d, dict) else None


def _dest_path(dest: dict) -> str | None:
    """create/rename destinations are either an existing file or dir+filename."""
    if not isinstance(dest, dict):
        return None
    if "existing_file" in dest:
        return _p(dest["existing_file"])
    np_ = dest.get("new_path")
    if isinstance(np_, dict):
        d = _p(np_.get("dir")) or ""
        return f"{d.rstrip('/')}/{np_.get('filename', '')}"
    return None


def normalize_es_event(ev: dict) -> dict | None:
    key = next(iter(ev["event"]))
    body = ev["event"][key]
    proc = ev["process"]
    out = {
        "t": parse_time(ev["time"]),
        "k": key,
        "pid": proc["audit_token"]["pid"],
        "ppid": proc.get("ppid"),
        "exe": _p(proc.get("executable")),
        "tty": proc.get("tty") is not None,
    }
    if key == "exec":
        target = body.get("target", {})
        out["exe"] = _p(target.get("executable")) or out["exe"]
        out["tty"] = target.get("tty") is not None
        out["args"] = body.get("args") or []
        out["cwd"] = _p(body.get("cwd"))
        # For `./script.sh` the executable is the interpreter; the script path is here.
        out["script"] = _p(body.get("script"))
        env = body.get("env") or []
        out["agent_env"] = sorted({e.split("=", 1)[0] for e in env
                                   if e.startswith(AGENT_ENV_PREFIXES)})
    elif key == "fork":
        out["child"] = body["child"]["audit_token"]["pid"]
    elif key == "exit":
        out["status"] = body.get("stat")
    elif key == "open":
        f = body.get("file", {})
        fflag = body.get("fflag", 0) or 0
        out["path"] = _p(f)
        out["read"] = bool(fflag & 1)
        out["wrote"] = bool(fflag & 2)
        out["trunc"] = bool(fflag & 0x400)  # O_TRUNC, e.g. `: > file`
        out["size"] = (f.get("stat") or {}).get("st_size")
    elif key == "close":
        out["path"] = _p(body.get("target"))
        out["wrote"] = bool(body.get("modified"))
    elif key == "create":
        out["path"] = _dest_path(body.get("destination"))
    elif key in ("write", "unlink", "truncate", "setmode", "chdir"):
        out["path"] = _p(body.get("target"))
        if key == "setmode":
            out["mode"] = body.get("mode")
    elif key == "rename":
        out["path"] = _p(body.get("source"))
        out["path2"] = _dest_path(body.get("destination"))
    elif key == "link":
        out["path"] = _p(body.get("source"))
        out["path2"] = f"{_p(body.get('target_dir')) or ''}/{body.get('target_filename', '')}"
    elif key == "btm_launch_item_add":
        out["k"] = "btm_add"
        out["path"] = json.dumps(body)[:500]
    elif key in ("sudo", "su", "setuid"):
        pass
    else:
        return None
    return out


def normalize_fs(raw_path: Path, out_path: Path) -> int:
    n = 0
    with open(raw_path, "rb") as fin, open(out_path, "w") as fout:
        last_write: dict[tuple, float] = {}
        for line in fin:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            e = normalize_es_event(ev)
            if e is None:
                continue
            # A single save can produce thousands of `write` events. Keep at
            # most one per (pid, path) per second; the features only need
            # "this file was modified around now".
            if e["k"] == "write":
                key = (e["pid"], e["path"])
                if e["t"] - last_write.get(key, -1e9) < 1.0:
                    continue
                last_write[key] = e["t"]
            fout.write(json.dumps(e) + "\n")
            n += 1
    return n


# ---------------------------------------------------------------- network ---

_PROC = re.compile(r"\bproc ([^,()]+?):(\d+)")
_EPROC = re.compile(r"\beproc ([^,()]+?):(\d+)")
_DIR = re.compile(r"[(,]\s*(in|out)\s*[,)]")
_ADDR = re.compile(
    r"\bIP6? (\S+)\.(\d+) > (\S+)\.(\d+): (?:(tcp|UDP|udp)[ ,]*(?:length )?(\d+))?")


def parse_tcpdump_line(line: str) -> dict | None:
    """Parse one line of `tcpdump -n -tt -q -k NPD -r file.pcapng`.

    The metadata format differs slightly across macOS versions, so this only
    relies on: a leading epoch timestamp, `proc NAME:PID`, an optional
    `eproc NAME:PID`, an optional `in`/`out` token, then the usual -q summary.
    """
    try:
        ts_s, rest = line.split(" ", 1)
        ts = float(ts_s)
    except ValueError:
        return None
    m = _ADDR.search(rest)
    if not m:
        return None
    head = rest[: m.start()]
    pm = _PROC.search(head)
    em = _EPROC.search(head)
    dm = _DIR.search(head)
    src, sport, dst, dport, proto, length = m.groups()
    return {
        "t": ts,
        "proc": pm.group(1).strip() if pm else None,
        "pid": int(pm.group(2)) if pm else None,
        "eproc": em.group(1).strip() if em else None,
        "epid": int(em.group(2)) if em else None,
        "dir": dm.group(1) if dm else None,
        "proto": (proto or "other").lower(),
        "src": src, "sport": int(sport), "dst": dst, "dport": int(dport),
        "len": int(length) if length else 0,
    }


def flow_key(p: dict) -> tuple:
    """Direction-independent connection key."""
    a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
    return (p["proto"],) + (a + b if a <= b else b + a)


def attribute_flows(parsed: list[dict]) -> dict:
    """Map each connection to the process that owns it.

    On current macOS, pktap tags inbound packets (`eproc curl:123`) but often
    prints outbound packets as a bare `(out)`. Uploads are exactly what the
    network features need, so any packet on a connection that names its
    process (eproc preferred, since `proc` is often kernel_task or
    mDNSResponder acting on someone's behalf) labels the whole connection.
    """
    owners: dict = {}
    for p in parsed:
        k = flow_key(p)
        if p.get("epid") is not None and p.get("eproc") != "kernel_task":
            owners[k] = (p["epid"], p["eproc"])
        elif p.get("pid") not in (None, 0) and k not in owners:
            owners[k] = (p["pid"], p["proc"])
    return owners


def _is_local(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def infer_dir(p: dict) -> str:
    if p.get("dir"):
        return p["dir"]
    # Fallback: the side with the lower (service) port is the server.
    return "out" if p["dport"] < p["sport"] else "in"


def find_tshark() -> str | None:
    for c in TSHARK_CANDIDATES:
        if shutil.which(c) or Path(c).exists():
            return c
    return None


def tls_and_dns_maps(pcap: Path) -> tuple[dict, dict]:
    """Return ({flow 4-tuple: (sni, ja4)}, {ip: hostname}) using tshark."""
    tshark = find_tshark()
    flows: dict = {}
    names: dict = {}
    if not tshark:
        return flows, names
    ch = subprocess.run(
        [tshark, "-r", str(pcap), "-Y", "tls.handshake.type==1", "-T", "fields",
         "-E", "separator=\t", "-e", "ip.src", "-e", "ipv6.src", "-e", "tcp.srcport",
         "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport",
         "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.ja4"],
        capture_output=True, text=True).stdout
    for row in ch.splitlines():
        c = row.split("\t")
        if len(c) < 8:
            continue
        src = c[0] or c[1]
        dst = c[3] or c[4]
        try:
            key = (src, int(c[2]), dst, int(c[5]))
        except ValueError:
            continue
        flows[key] = (c[6], c[7])
        if c[6]:
            names.setdefault(dst, c[6])
    dns = subprocess.run(
        [tshark, "-r", str(pcap), "-Y", "dns.flags.response==1", "-T", "fields",
         "-E", "separator=\t", "-E", "aggregator=,",
         "-e", "dns.qry.name", "-e", "dns.a", "-e", "dns.aaaa"],
        capture_output=True, text=True).stdout
    for row in dns.splitlines():
        c = row.split("\t")
        if len(c) < 2 or not c[0]:
            continue
        qname = c[0].split(",")[0]
        for ip in ",".join(c[1:]).split(","):
            if ip:
                names.setdefault(ip, qname)
    return flows, names


def normalize_net(pcap: Path, pids: set[int], out_path: Path,
                  sample_path: Path | None = None) -> dict:
    """Decode pcapng, keep packets owned by the tracked pids, label hosts."""
    stats = {"packets": 0, "kept": 0, "unattributed": 0}
    if not pcap.exists() or pcap.stat().st_size == 0:
        out_path.write_text("")
        return stats
    proc = subprocess.run(["/usr/sbin/tcpdump", "-n", "-tt", "-q", "-k", "NPD", "-r", str(pcap)],
                          capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    if sample_path is not None:
        sample_path.write_text("\n".join(lines[:200]))
    flows, names = tls_and_dns_maps(pcap)
    parsed = [p for p in map(parse_tcpdump_line, lines) if p]
    owners = attribute_flows(parsed)
    with open(out_path, "w") as f:
        for p in parsed:
            stats["packets"] += 1
            if p["pid"] is None and p["epid"] is None:
                owner = owners.get(flow_key(p))
                if owner:
                    p["epid"], p["eproc"] = owner
                    stats["flow_attributed"] = stats.get("flow_attributed", 0) + 1
                else:
                    stats["unattributed"] += 1
            if p["pid"] not in pids and p["epid"] not in pids:
                continue
            p["dir"] = infer_dir(p)
            remote = p["dst"] if p["dir"] == "out" else p["src"]
            fwd = (p["src"], p["sport"], p["dst"], p["dport"])
            rev = (p["dst"], p["dport"], p["src"], p["sport"])
            sni, ja4 = flows.get(fwd) or flows.get(rev) or ("", "")
            p["host"] = sni or names.get(remote, "") or ("localhost" if remote in ("127.0.0.1", "::1") else "")
            p["remote"] = remote
            p["remote_local"] = _is_local(remote)
            if fwd in flows:
                p["ja4"] = ja4
            f.write(json.dumps(p) + "\n")
            stats["kept"] += 1
    return stats


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(x) for x in f if x.strip()]


def ingest_run(run_dir: Path) -> dict:
    """Normalize one run's captures in place. Safe to re-run."""
    run_dir = Path(run_dir)
    result: dict = {}
    pids_file = run_dir / "pids.json"
    pids = set(json.loads(pids_file.read_text()).get("pids", [])) if pids_file.exists() else set()
    if (run_dir / "fs_raw.jsonl").exists():
        result["fs_events"] = normalize_fs(run_dir / "fs_raw.jsonl", run_dir / "fs.jsonl")
    if (run_dir / "net.pcapng").exists():
        result["net"] = normalize_net(run_dir / "net.pcapng", pids, run_dir / "net.jsonl",
                                      run_dir / "tcpdump_sample.txt")
    return result
