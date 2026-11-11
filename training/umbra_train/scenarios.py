"""Load scenario definitions from scenarios/{approved,unapproved}/*.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .config import SCENARIOS_DIR

CHECK_TYPES = {"command_succeeds", "file_exists", "file_contains", "file_unchanged",
               "dir_empty", "file_size_max", "git_commits_min", "sink_received"}


@dataclass
class Scenario:
    id: str
    label: str  # approved | unapproved
    category: str
    title: str
    prompt: str
    script: str
    timeout_s: int
    scope: list[str]
    checks: list[dict] = field(default_factory=list)
    human_hint: str = ""  # commented walkthrough printed only on human runs
    source: Path | None = None


def _load(path: Path) -> Scenario:
    raw = tomllib.loads(path.read_text())
    sc = Scenario(
        id=raw["id"],
        label=raw["label"],
        category=raw["category"],
        title=raw.get("title", raw["id"]),
        prompt=raw["prompt"].strip(),
        script=raw.get("script", "").strip(),
        timeout_s=int(raw.get("timeout_s", 600)),
        scope=list(raw.get("scope", [])),
        checks=list(raw.get("check", [])),
        human_hint=raw.get("human_hint", "").strip("\n"),
        source=path,
    )
    validate(sc)
    return sc


def validate(sc: Scenario) -> None:
    problems = []
    if sc.label not in ("approved", "unapproved"):
        problems.append(f"label must be approved|unapproved, got {sc.label!r}")
    if sc.source and sc.source.parent.name != sc.label:
        problems.append(f"file is in {sc.source.parent.name}/ but label is {sc.label}")
    if not sc.checks:
        problems.append("needs at least one [[check]] so outcomes can be tracked")
    for c in sc.checks:
        if c.get("type") not in CHECK_TYPES:
            problems.append(f"unknown check type {c.get('type')!r}")
    if not sc.script:
        problems.append("needs a `script` (the automation baseline)")
    if problems:
        raise ValueError(f"scenario {sc.id}: " + "; ".join(problems))


def load_all() -> dict[str, Scenario]:
    out = {}
    for p in sorted(SCENARIOS_DIR.glob("*/*.toml")):
        sc = _load(p)
        if sc.id in out:
            raise ValueError(f"duplicate scenario id {sc.id}")
        out[sc.id] = sc
    return out


def select(spec: str) -> list[Scenario]:
    """'all' | 'approved' | 'unapproved' | comma list of ids or id prefixes."""
    allsc = load_all()
    if spec in ("all", ""):
        return list(allsc.values())
    if spec in ("approved", "unapproved"):
        return [s for s in allsc.values() if s.label == spec]
    picked = []
    for token in spec.split(","):
        token = token.strip()
        matches = [s for k, s in allsc.items() if k == token or k.startswith(token + "_") or k.startswith(token)]
        if not matches:
            raise ValueError(f"no scenario matches {token!r}; have {', '.join(allsc)}")
        picked.extend(m for m in matches if m not in picked)
    return picked
