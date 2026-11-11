"""umbra-train: run, track and evaluate Umbra training sessions."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time

from . import experiments, ingest, report, runner, scenarios, timing, tracker
from .config import DATA_DIR, RUNS_DIR, SENSOR_SCRIPT, load_lab_config
from .lab import Sink


def cmd_doctor(a):
    out = DATA_DIR / "doctor" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    if runner.IS_WINDOWS:
        from .capture import windows
        print("Checking the Windows sensors (ETW, Security 4688, pktmon). Needs an elevated prompt.\n")
        rc = windows.doctor(out)
        if rc == 0:
            print("Sensors OK. Next: uv run umbra-train run --actor script --scenario all")
        return rc
    print("Checking the sensors. sudo will ask for your password.\n")
    rc = subprocess.run(["sudo", sys.executable, "-I", str(SENSOR_SCRIPT), "--doctor",
                         "--run-dir", str(out)]).returncode
    print(f"\nSample output saved in {out}")
    if rc == 0:
        print("Sensors OK. Next: uv run umbra-train run --actor script --scenario all")
    return rc


def cmd_scenarios(a):
    for s in scenarios.load_all().values():
        print(f"{s.id:28} {s.label:11} {s.category:22} {s.title}")


def cmd_run(a):
    lab = load_lab_config()
    actor_names = [x.strip() for x in a.actor.split(",")]
    for n in actor_names:
        if n not in lab.actors:
            raise SystemExit(f"unknown actor {n!r}; have {', '.join(lab.actors)}")
    picked = scenarios.select(a.scenario)
    total = len(actor_names) * len(picked) * a.reps
    keeper = runner.SudoKeeper().start() if not a.no_capture else None
    sink = Sink().start()
    i = 0
    try:
        for rep in range(1, a.reps + 1):
            for sc in picked:
                for n in actor_names:
                    i += 1
                    print(f"[{i}/{total}] {n} × {sc.id} (rep {rep}) ...", flush=True)
                    try:
                        m = runner.run_one(lab.actors[n], sc, lab, sink, rep=rep,
                                           capture=not a.no_capture, timeout_s=a.timeout)
                    except runner.CaptureUnavailable as e:
                        print(f"\nStopping the batch: the sensor could not start, so no actor was run.\n  {e}\n"
                              "Check `uv run umbra-train doctor` from this same terminal.")
                        return 2
                    print(f"        {m['status']}, outcome={m.get('outcome')} "
                          f"({m.get('checks_passed')}/{m.get('checks_total')} checks), "
                          f"{m.get('duration_s')}s, fs={m.get('fs_events', '-')} pkts={m.get('net_packets', '-')}"
                          + (f"\n        note: {m['notes']}" if m.get("notes") else ""), flush=True)
    finally:
        sink.stop()
        if keeper:
            keeper.stop()
    print(f"\nreport: {report.write_report()}")


def cmd_status(a):
    actors, scen, cells = tracker.matrix()
    if not actors:
        print("no runs yet")
        return
    w = max(len(s) for s in scen) + 2
    print("scenario".ljust(w) + "".join(x[:16].ljust(18) for x in actors))
    for s in scen:
        line = s.ljust(w)
        for x in actors:
            c = cells.get((x, s))
            line += (f"{c['completed']}/{c['n']} ok, {c['captured']} cap" if c else "-").ljust(18)
        print(line)


def cmd_ingest(a):
    runs = [r["run_id"] for r in tracker.all_runs()] if a.run == "all" else [a.run]
    for rid in runs:
        print(rid, json.dumps(ingest.ingest_run(RUNS_DIR / rid)))


def cmd_timeline(a):
    """Merged network + filesystem timeline with agent-loop legs annotated."""
    from pathlib import Path
    run_dir = Path(a.run) if Path(a.run).is_dir() else RUNS_DIR / a.run
    if not (run_dir / "fs.jsonl").exists() and (run_dir / "fs_raw.jsonl").exists():
        ingest.ingest_run(run_dir)
    fs = ingest.load_jsonl(run_dir / "fs.jsonl")
    net = ingest.load_jsonl(run_dir / "net.jsonl")
    pids = json.loads((run_dir / "pids.json").read_text()) if (run_dir / "pids.json").exists() else {}
    root = pids.get("root")
    print(timing.format_timeline(timing.timeline(fs, net, root), limit=a.limit))
    feats = timing.compute(fs, net, root)
    print("\n" + "  ".join(f"{k}={v:.3g}" for k, v in feats.items()))


def cmd_train(a):
    res = experiments.train_and_report()
    print(f"{res['n_sessions']} sessions, {res['n_windows']} windows")
    for exp in res.get("experiments", []):
        print(f"\n{exp['question']}")
        for v in exp["variants"]:
            if "skipped" in v:
                print(f"  {v['features']:42} skipped: {v['skipped']}")
            else:
                print(f"  {v['features']:42} balanced acc {v['balanced_accuracy']:.2f} (chance {v['chance']:.2f}), "
                      f"n={v['n']}, top: {', '.join(c for c, _ in v['top_features'][:3])}")
        if exp.get("rule_baseline"):
            print(f"  rule baseline: {exp['rule_baseline']['accuracy']:.2f} ({exp['rule_baseline']['rule']})")
    print(f"\nreport: {report.write_report(res)}")


def cmd_report(a):
    print(report.write_report())


def cmd_sink(a):
    s = Sink().start()
    print(f"sink listening on http://{s.host}:{s.port} (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        s.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="umbra-train", description=__doc__)
    sp = ap.add_subparsers(dest="cmd", required=True)
    sp.add_parser("doctor", help="check eslogger + pktap capture work on this Mac (needs sudo)").set_defaults(fn=cmd_doctor)
    sp.add_parser("scenarios", help="list scenarios").set_defaults(fn=cmd_scenarios)
    r = sp.add_parser("run", help="run actor(s) through scenario(s) with capture")
    r.add_argument("--actor", required=True, help="claude_code, codex, human, script (comma list ok)")
    r.add_argument("--scenario", default="all", help="all | approved | unapproved | ids/prefixes, e.g. a01,u02")
    r.add_argument("--reps", type=int, default=1)
    r.add_argument("--timeout", type=int, default=None, help="override per-scenario timeout (s)")
    r.add_argument("--no-capture", action="store_true", help="skip sensors (dry run, no sudo)")
    r.set_defaults(fn=cmd_run)
    sp.add_parser("status", help="scenario × actor coverage").set_defaults(fn=cmd_status)
    i = sp.add_parser("ingest", help="re-normalize raw captures")
    i.add_argument("--run", default="all")
    i.set_defaults(fn=cmd_ingest)
    t = sp.add_parser("timeline", help="show a run's merged network + filesystem timeline with loop timings")
    t.add_argument("run", help="run id (or a run directory path)")
    t.add_argument("--limit", type=int, default=200)
    t.set_defaults(fn=cmd_timeline)
    sp.add_parser("train", help="build features, run feasibility experiments, write report").set_defaults(fn=cmd_train)
    sp.add_parser("report", help="rewrite the HTML dashboard").set_defaults(fn=cmd_report)
    sp.add_parser("sink", help="run the localhost sink alone (for manual testing)").set_defaults(fn=cmd_sink)
    a = ap.parse_args(argv)
    return a.fn(a) or 0


if __name__ == "__main__":
    sys.exit(main())
