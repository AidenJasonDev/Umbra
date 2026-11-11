"""Paths and lab settings. Everything lives under training/ except sandboxes."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

TRAINING_DIR = Path(__file__).resolve().parent.parent
SCENARIOS_DIR = TRAINING_DIR / "scenarios"
TEMPLATE_DIR = TRAINING_DIR / "templates" / "workspace"
ACTORS_FILE = TRAINING_DIR / "actors.toml"
DATA_DIR = Path(os.environ.get("UMBRA_DATA_DIR", TRAINING_DIR / "data"))
RUNS_DIR = DATA_DIR / "runs"
REPORTS_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "umbra.db"
SENSOR_SCRIPT = Path(__file__).resolve().parent / "capture" / "sensor.py"

# Sandboxes live outside the repo so an agent that explores upward finds an
# empty lab directory, not Umbra's training code or other runs' captures.
SANDBOX_ROOT = Path(os.environ.get("UMBRA_SANDBOX_ROOT", Path.home() / "UmbraLab" / "sandboxes"))

SINK_HOST = "127.0.0.1"
SINK_PORT = int(os.environ.get("UMBRA_SINK_PORT", "8765"))

# Hosts that count as "LLM API" for marker features (suffix match).
LLM_HOST_SUFFIXES = (
    "anthropic.com", "claude.ai", "claude.com",
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "generativelanguage.googleapis.com", "x.ai", "cursor.sh", "cursor.com",
)

# Env vars that would leak agent identity into child processes. The runner
# strips these before launching any actor, so a human or script run started
# from inside an agent's terminal doesn't inherit them.
SCRUB_ENV_PREFIXES = ("CLAUDECODE", "CLAUDE_CODE", "CLAUDE_AGENT", "AI_AGENT", "CODEX_",
                      "ANTHROPIC_", "OPENAI_", "CURSOR_", "GEMINI_CLI", "AIDER_",
                      "MCP_", "CCD_")


@dataclass
class Actor:
    name: str
    kind: str  # agent | human | script
    cmd: list[str] = field(default_factory=list)
    is_agent: bool = False
    env: dict = field(default_factory=dict)
    isolated_home: str | None = None  # env var to point at a clean per-lab home


@dataclass
class LabConfig:
    preamble: str
    actors: dict[str, Actor]


def load_lab_config(path: Path = ACTORS_FILE) -> LabConfig:
    raw = tomllib.loads(path.read_text())
    actors = {}
    for name, a in raw.get("actors", {}).items():
        cmd = a.get("cmd_windows") if (os.name == "nt" and "cmd_windows" in a) else a.get("cmd", [])
        actors[name] = Actor(
            name=name,
            kind=a["kind"],
            cmd=list(cmd),
            is_agent=a["kind"] == "agent",
            env=dict(a.get("env_windows") if (os.name == "nt" and "env_windows" in a) else a.get("env", {})),
            isolated_home=a.get("isolated_home"),
        )
    return LabConfig(preamble=raw.get("lab", {}).get("preamble", "").strip(), actors=actors)
