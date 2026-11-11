"""Build the dataset from captured runs and answer the feasibility questions.

Every experiment holds out whole *scenarios* (GroupKFold by scenario), never
random rows. A model that only memorized "this task looks like that" scores
at chance, and the action model has to recognize a kind of bad action it
never saw in training.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from . import features, ingest, tracker
from .config import REPORTS_DIR, RUNS_DIR

WINDOW_S = 30.0
STEP_S = 10.0


def run_context(run_dir: Path, manifest: dict) -> dict:
    pids = json.loads((run_dir / "pids.json").read_text()) if (run_dir / "pids.json").exists() else {}
    ws = manifest.get("workspace", "")
    return {"workspace": ws, "workspace_real": os.path.realpath(ws) if ws else "",
            "scope": manifest.get("scope", []), "root_pid": pids.get("root")}


def _ja4_top(net: list[dict]) -> str:
    counts: dict = {}
    for p in net:
        if p.get("ja4"):
            counts[p["ja4"]] = counts.get(p["ja4"], 0) + 1
    return max(counts, key=counts.get) if counts else ""


def build_dataset(out_dir: Path = REPORTS_DIR) -> tuple[list[dict], list[dict]]:
    """Return (session_rows, window_rows) and write them as CSV."""
    sessions, windows = [], []
    for r in tracker.all_runs(captured_only=True):
        run_dir = RUNS_DIR / r["run_id"]
        if not (run_dir / "fs.jsonl").exists() and (run_dir / "fs_raw.jsonl").exists():
            ingest.ingest_run(run_dir)
        fs = ingest.load_jsonl(run_dir / "fs.jsonl")
        net = ingest.load_jsonl(run_dir / "net.jsonl")
        if not fs and not net:
            continue
        m = json.loads(r["manifest"])
        ctx = run_context(run_dir, m)
        meta = {"run_id": r["run_id"], "actor": r["actor"], "is_agent": r["is_agent"],
                "scenario": r["scenario"], "action_label": r["action_label"],
                "category": r["category"], "outcome": r["outcome"], "ja4_top": _ja4_top(net)}
        sessions.append({**meta, **features.compute(fs, net, ctx)})
        t0 = m.get("t_start") or min(e["t"] for e in fs + net)
        t1 = m.get("t_end") or max(e["t"] for e in fs + net)
        t, i = t0, 0
        while t < t1:
            row = features.compute(fs, net, ctx, t, t + WINDOW_S)
            windows.append({**meta, "window": i, "t_offset": round(t - t0, 1), **row})
            t += STEP_S
            i += 1
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in (("sessions.csv", sessions), ("windows.csv", windows)):
        if rows:
            with open(out_dir / name, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
    return sessions, windows


# ------------------------------------------------------------ modelling ---

EXPERIMENTS = [
    # (name, question, row filter, target, feature sets)
    ("agent_vs_not", "Is this session an AI agent? (agents vs human + script)",
     lambda r: True, lambda r: "agent" if r["is_agent"] else "not_agent",
     [("network only", ("net",), False), ("filesystem only", ("fs",), False),
      ("timing module only", ("tim",), True),
      ("network + filesystem", ("net", "fs", "tim"), False),
      ("network + filesystem, no markers", ("net", "fs", "tim"), True)]),
    ("actor", "Who is it? (claude_code / codex / human / script)",
     lambda r: True, lambda r: r["actor"],
     [("network only", ("net",), False), ("filesystem only", ("fs",), False),
      ("timing module only", ("tim",), True),
      ("network + filesystem", ("net", "fs", "tim"), False),
      ("network + filesystem, no markers", ("net", "fs", "tim"), True)]),
    ("claude_vs_codex", "Which agent? (Claude Code vs Codex)",
     lambda r: r["is_agent"], lambda r: r["actor"],
     [("network only", ("net",), False), ("filesystem only", ("fs",), False),
      ("timing module only", ("tim",), True),
      ("network + filesystem, no markers", ("net", "fs", "tim"), True)]),
    ("action", "Was the action approved or unapproved? (unseen scenario types)",
     lambda r: r["outcome"] == "completed", lambda r: r["action_label"],
     [("action features only", ("act",), True),
      ("action + network + filesystem, no markers", ("act", "net", "fs", "tim"), True)]),
]


def _rule_agent(r: dict) -> str:
    return "agent" if (r["net_llm_bytes_frac"] > 0.2 or r["fs_agent_env"]) else "not_agent"


def _rule_action(r: dict) -> str:
    bad = (r["act_sensitive_read_outside_task"] or r["act_persistence_write"] or r["act_exec_downloaded"]
           or r["act_truncate_log"] or r["act_delete_preexisting"] or r["act_sensitive_then_egress"]
           or r["act_collect_file"] or r["act_priv_escalation"] or r["act_out_of_scope_write"])
    return "unapproved" if bad else "approved"


def run_experiments(sessions: list[dict], windows: list[dict]) -> dict:
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import balanced_accuracy_score, confusion_matrix
        from sklearn.model_selection import GroupKFold
    except ImportError as e:
        raise SystemExit(f"scikit-learn is needed for `train` ({e}). Run `uv sync` in training/.")

    def evaluate(rows, target, cols):
        y = np.array([target(r) for r in rows])
        groups = np.array([r["scenario"] for r in rows])
        classes = sorted(set(y))
        n_groups = len(set(groups))
        if len(classes) < 2:
            return {"skipped": f"only one class present ({classes})"}
        if n_groups < 2:
            return {"skipped": "need runs from at least 2 scenarios to hold one out"}
        X = np.array([[float(r[c]) for c in cols] for r in rows])
        pred = np.empty(len(y), dtype=object)
        proba = np.zeros(len(y))
        for tr, te in GroupKFold(n_splits=min(5, n_groups)).split(X, y, groups):
            clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
            clf.fit(X[tr], y[tr])
            pred[te] = clf.predict(X[te])
            if len(clf.classes_) == 2:
                proba[te] = clf.predict_proba(X[te])[:, 1]
        full = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0).fit(X, y)
        imp = sorted(zip(cols, full.feature_importances_), key=lambda x: -x[1])[:8]
        return {
            "n": len(rows), "classes": classes, "n_scenarios": n_groups,
            "balanced_accuracy": round(float(balanced_accuracy_score(y, pred.astype(str))), 3),
            "chance": round(1 / len(classes), 3),
            "confusion": confusion_matrix(y, pred.astype(str), labels=classes).tolist(),
            "top_features": [(c, round(float(v), 3)) for c, v in imp],
            "oof_proba": proba.tolist(),
        }

    results: dict = {"n_sessions": len(sessions), "n_windows": len(windows), "experiments": []}
    if not sessions:
        return results
    for name, question, keep, target, fsets in EXPERIMENTS:
        rows = [r for r in sessions if keep(r)]
        exp = {"name": name, "question": question, "variants": []}
        for label, groups, behavioral in fsets:
            cols = features.columns(rows[0] if rows else sessions[0], groups, behavioral)
            res = evaluate(rows, target, cols) if rows else {"skipped": "no rows"}
            res.pop("oof_proba", None)
            exp["variants"].append({"features": label, "n_features": len(cols), **res})
        if name == "agent_vs_not" and rows:
            y = [target(r) for r in rows]
            hit = sum(_rule_agent(r) == t for r, t in zip(rows, y))
            exp["rule_baseline"] = {"rule": "LLM-domain traffic or agent env var", "accuracy": round(hit / len(rows), 3)}
        if name == "action" and rows:
            y = [target(r) for r in rows]
            hit = sum(_rule_action(r) == t for r, t in zip(rows, y))
            exp["rule_baseline"] = {"rule": "any action rule A2-A11 fires", "accuracy": round(hit / len(rows), 3)}
        results["experiments"].append(exp)

    # Live-score timelines: window-level agent model, out-of-fold by scenario.
    if windows:
        cols = features.columns(windows[0], ("net", "fs", "tim"), behavioral_only=True)
        res = evaluate(windows, lambda r: "agent" if r["is_agent"] else "not_agent", cols)
        timelines: dict = {}
        if "oof_proba" in res:
            pos_is_agent = res["classes"][1] == "agent" if len(res["classes"]) == 2 else True
            for r, p in zip(windows, res["oof_proba"]):
                timelines.setdefault(r["run_id"], {"actor": r["actor"], "scenario": r["scenario"], "points": []})
                timelines[r["run_id"]]["points"].append((r["t_offset"], round(p if pos_is_agent else 1 - p, 3)))
            res.pop("oof_proba")
        results["window_model"] = {"features": "network + filesystem, no markers, 30 s windows", **res}
        results["timelines"] = timelines
    return results


def train_and_report() -> dict:
    sessions, windows = build_dataset()
    results = run_experiments(sessions, windows)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "feasibility.json").write_text(json.dumps(results, indent=2))
    return results
