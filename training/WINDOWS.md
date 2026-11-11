# Umbra on Windows

The Windows sensor ([umbra_train/capture/windows.py](umbra_train/capture/windows.py)) writes the
same `fs.jsonl` / `net.jsonl` the Mac sensor does. Features, the timing module, experiments and
the report run unchanged. Scenarios, checks and the tracker are shared too.

> **Status:** the sensor is written against the documented ETW provider manifests and tested here
> with synthetic ETW XML, but it has **not yet run on Windows hardware**. Run `doctor` first.
> It keeps raw `etw.xml` / `sec4688.xml` samples so field names can be checked and fixed.

## What replaces what

| Mac | Windows | Built in? |
|---|---|---|
| eslogger exec/fork/exit | ETW `Microsoft-Windows-Kernel-Process` + Security **4688** (full command lines) | yes |
| eslogger open/write/create/rename/unlink | ETW `Microsoft-Windows-Kernel-File` | yes |
| pktap per-packet process | ETW `Microsoft-Windows-Kernel-Network`: every TCP/UDP send/recv with PID, size and endpoints | yes |
| DNS from tshark | ETW `Microsoft-Windows-DNS-Client` 3008, which includes the requesting PID | yes |
| pcapng for SNI/JA4 | `pktmon` → pcapng → the same tshark code | pktmon yes, tshark no |
| sudo + Full Disk Access | an elevated prompt ("Run as administrator") | yes |
| `sh -c 'exec "$@"' marker` | the runner passes the actor's PID; the tree is rebuilt from ProcessStart parent links | — |

ETW is recorded to disk with `logman` during the run, then converted with `tracerpt` and filtered
to the actor's process tree. Because the whole run is on disk, early events can't be lost to a race.

## Setup (once)

In **PowerShell, Run as administrator**:

```powershell
winget install astral-sh.uv Git.Git WiresharkFoundation.Wireshark
npm install -g @anthropic-ai/claude-code @openai/codex   # then sign in to both
git clone https://github.com/AidenJasonDev/Umbra.git
cd Umbra\training
uv sync
uv run umbra-train doctor
```

`doctor` turns on command-line auditing for event 4688 (`auditpol` plus one registry value), runs
`curl.exe` under the sensor, and checks that it captured:

- process events
- the full command line
- file events
- send and receive traffic with a PID
- the `example.com` host label

## Run

Same commands as on the Mac, from the elevated prompt:

```powershell
uv run umbra-train run --actor script,claude_code,codex --scenario all
uv run umbra-train run --actor human --scenario all      # opens PowerShell; type `exit` when done
uv run umbra-train train
```

The script actor runs the scenario scripts with Git for Windows' bash
(`C:/Program Files/Git/bin/bash.exe`). The full path is set in `actors.toml` because a bare
`bash.exe` can resolve to the WSL launcher.

## Features that differ on Windows

| Feature | On Windows |
|---|---|
| `fs_tty_frac` | Always 0. Windows has no TTY. Something like a ConPTY/console-session check would be needed |
| `fs_agent_env` | Always 0. ETW doesn't expose a process's environment |
| `fs_sandbox_exec` | Always 0. That's a Codex-on-macOS marker |
| Shell one-liners (F3, F5–F7) | `cmd /c`, `powershell -Command`, `-EncodedCommand` (decoded) and `pwsh` are recognized |
| Persistence (A6) | Startup folders, PowerShell profiles, `System32/Tasks`, and `reg add …\CurrentVersion\Run`, `schtasks /create`, `Register-ScheduledTask`, `sc create` in command lines. Registry writes themselves need ETW `Microsoft-Windows-Kernel-Registry` (not wired yet) |
| Download and execute (A7) | Also `iwr`/`irm`/`DownloadString` piped into `iex` |
| Sensitive reads (A1) | Also DPAPI `Credentials`/`Protect`, `Vault`, browser `Login Data`/`Cookies`, `.kdbx` |

The network loop and timing features don't depend on the OS. On Windows they get **better**
input, because every send event carries its PID.

A model trained on Mac runs won't transfer as-is. Collect the same scenarios on Windows and train
per OS, or with an `os` column.

## Disposable environments

**Windows Sandbox** (built in on Pro and Enterprise) is the simplest throwaway VM. Use a `.wsb`
file with a `LogonCommand` that runs the batch. It has historically allowed only one instance at a
time, so use Hyper-V checkpoints for parallel runs.
