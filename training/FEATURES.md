# Umbra training parameters

These are the features the model trains on. Every one is computed only from two sensors:

- **Network**: Apple `tcpdump -i pktap,all`, which tags every packet with the process that sent or received it. `tshark` adds TLS SNI, JA4 fingerprints and DNS answers.
- **Filesystem/process**: Apple `eslogger` (Endpoint Security), which gives exec, fork, exit, open, close, create, write, rename, unlink, truncate and setmode events, with argv, env, cwd and tty.

Features are computed per **actor session**: one process tree, rooted at whatever started the work (the `claude` harness, the `codex` harness, or a human's interactive shell). Each session is scored as a whole and also over sliding windows (30 s window, 10 s step) so the score can update live.

Every feature has a **class**:

- **behavioral**: comes from how the actor works. This is what has to survive an attacker who renames binaries and strips env vars.
- **marker**: an identity tell, such as a known LLM domain, an env var or a harness binary. It is useful for labeling and attribution, but an attacker can remove it. The model is trained and reported **with and without** markers, so we can see whether behavior alone carries the signal.

Column names match `umbra_train/features.py`.

---

## 1. Network features (flagship)

The core idea: an agent must send its context to a model and wait for the answer before every action. That loop shows up on the wire even when the traffic is encrypted.

| ID | Feature | Class | What it measures | Why it separates actors |
|---|---|---|---|---|
| N1 | `net_llm_bytes_frac` | marker | Share of the session's bytes going to known LLM API hosts (by SNI/DNS) | Direct identity tell; Claude talks to `api.anthropic.com`, Codex to `chatgpt.com` / `api.openai.com` |
| N2 | `ja4_top` | marker | Most common TLS client fingerprint (JA4) in the session. Stored per run in `sessions.csv` for attribution analysis; not a model input in v0 because it's a string | Node (Claude Code) and Rust/rustls (Codex) produce different ClientHellos |
| N3 | `net_turns_per_min` | behavioral | Upload bursts (client→server, ≥1 KB within 300 ms) per minute on long-lived TLS flows | Each agent "turn" is one upload of context |
| N4 | `net_upload_growth` | behavioral | Spearman correlation between turn index and upload size | Context accumulates, so each request is larger than the last. Humans browsing don't do this |
| N5 | `net_stream_frac` | behavioral | Share of downstream bytes arriving as token streams (≥20 small inbound packets, 5–300 ms apart) | Server-sent token streaming has a distinctive rhythm |
| N6 | `net_stream_ia_median_ms` | behavioral | Median inter-arrival time inside streams | Roughly the model's tokens per second; differs by vendor |
| N7 | `net_think_act_frac` | behavioral | Share of local exec bursts that start within 2 s after a download stream ends | **The agent loop: model answers, then a tool runs.** Cross-sensor |
| N8 | `net_act_report_frac` | behavioral | Share of uploads that start within 3 s after a local process exits | The tool result is sent straight back to the model |
| N9 | `net_upload_vs_read_corr` | behavioral | Correlation between bytes of files read in an action and the size of the next upload | Agents send what they just read back up |
| N10 | `net_distinct_hosts` | behavioral | Distinct remote hosts contacted | |
| N11 | `net_nonllm_egress_bytes` | behavioral | Bytes uploaded to hosts that are not LLM APIs | Package installs, docs fetches, and exfiltration |
| N12 | `net_max_flow_concurrency` | behavioral | Most simultaneously open flows | |
| N13 | `net_loopback_egress_bytes` | behavioral | Bytes uploaded to localhost services | In the lab, exfiltration lands on a localhost sink |

## 2. Filesystem and process features (eslogger)

| ID | Feature | Class | What it measures | Why it separates actors |
|---|---|---|---|---|
| F1 | `fs_exec_per_min` | behavioral | Process launches per minute | |
| F2 | `fs_exec_gap_median_s` / `fs_exec_gap_cv` | behavioral | Median and coefficient of variation of gaps between command launches | Agents pause for the model (a few seconds, fairly regular); humans are irregular |
| F3 | `fs_shell_c_frac` | behavioral | Share of shells started as `sh/bash/zsh -c "<one-liner>"` | Agents run commands through non-interactive shells |
| F4 | `fs_tty_frac` | behavioral ⚠ | Share of execs with a controlling terminal | Humans have a TTY; headless agents usually don't. **Depends on how the agent was launched**: Claude Code or Codex used interactively in a terminal *do* have a TTY. Training is headless for now, so this feature can overfit; add interactive-agent runs before trusting it |
| F5 | `fs_output_limit_frac` | behavioral | Share of commands containing `\| head`, `\| tail`, `2>&1`, `sed -n` | Agents cap output to save context |
| F6 | `fs_noninteractive_flag_frac` | behavioral | Share of commands with `-y`, `--yes`, `--no-pager`, `-q`, `GIT_PAGER=cat` | Agents can't answer prompts |
| F7 | `fs_cmd_len_median` / `fs_cmd_len_p90` | behavioral | Length of the command line | Agents write long one-liners and heredocs |
| F8 | `fs_atomic_write_frac` | behavioral | Share of file modifications done as create-temp-then-rename | How the harness's edit tool saves files |
| F9 | `fs_read_before_write_frac` | behavioral | Share of modified files that the same session read in the previous 60 s | Agents read a file, then rewrite it |
| F10 | `fs_open_per_min` / `fs_distinct_dirs` | behavioral | File reads per minute, and how many directories were touched | Agents explore breadth-first |
| F11 | `fs_editor_exec` | behavioral | Interactive editor launched (vim, nano, emacs, code) | Human tell |
| F12 | `fs_parallel_spawn_frac` | behavioral | Share of execs starting within 50 ms of another from the same parent | Parallel tool calls |
| F13 | `fs_retry_after_fail` | behavioral | Commands relaunched within 20 s after a nonzero exit | Fast near-identical retries |
| F14 | `fs_first_action_s` | behavioral | Seconds from session start to first command | |
| F15 | `fs_chdir_count` | behavioral | Directory changes | Humans `cd` around; agents use absolute paths |
| F16 | `fs_sandbox_exec` | marker | `sandbox-exec` launched in the tree | Codex runs commands inside Apple's seatbelt sandbox |
| F17 | `fs_agent_env` | marker | Exec env has `CLAUDECODE`, `CODEX_*`, `AI_AGENT` and similar | Identity tell (also used for ground-truth labels) |
| F18 | `fs_harness_state_access` | marker | Touches `~/.claude/` or `~/.codex/` | Harness bookkeeping files |

## 3. Timing module (`umbra_train/timing.py`)

Both sensors stamp events from the same system clock: eslogger in nanoseconds, pktap in
microseconds. On this Mac, a curl's first SYN lands 25 ms after its exec event, and every one of
its packets falls inside its exec→exit window. So network and filesystem events can be compared
at millisecond resolution. The module rebuilds the agent loop and times each leg:

```
upload ──ttft──▶ stream start ──gen──▶ stream end ──dispatch──▶ cmd start ──tool──▶ cmd end ──report──▶ next upload
```

All timing features are **behavioral**. They use no domains, names or env vars.

| ID | Feature | What it measures | Why it separates actors |
|---|---|---|---|
| T1 | `tim_cycles` / `tim_cycle_cmd_frac` | Complete upload → stream → command → upload cycles, and the share of commands inside one | Only something driven by a model's answers closes this loop |
| T2 | `tim_dispatch_median_ms` / `tim_dispatch_cv` | Delay from the model's last token to the next command, and how much it varies | **Key signal.** A harness reacts in milliseconds and regularly. A human, even one pasting from a chatbot, takes seconds and varies |
| T3 | `tim_dispatched_cmd_frac` | Share of commands that start within 5 s after a token stream ends | |
| T4 | `tim_report_median_ms` / `tim_report_cv` | Delay from a command exiting to the next upload | The tool result goes straight back to the model |
| T5 | `tim_ttft_median_s` | Upload → first token | Model or vendor latency (attribution) |
| T6 | `tim_gen_median_s` | Token-stream duration | Answer length × tokens per second |
| T7 | `tim_period_median_s` / `tim_period_cv` | Time between turns, and how regular it is | |
| T8 | `tim_tool_median_s` | How long commands run | |
| T9 | `tim_cmd_burstiness` | Goh–Barabási burstiness of command gaps (−1 periodic, 0 random, ~1 bursty) | Human activity is bursty, agent activity is closer to periodic |
| T10 | `tim_net_quiet_cmd_frac` | Share of commands with no internet traffic in the 10 s before | Humans and scripts act without consulting a model |

`umbra-train timeline <run>` prints the merged, annotated timeline for one run, and every run saves
it as `timeline.json`. That's the raw material for the demo video:

```
+  12.031s  net  upload       18.2 KB -> api.anthropic.com            [report 640 ms]
+  12.904s  net  stream start 212 pkts, 31 ms apart                   [ttft 870 ms]
+  19.511s  net  stream end   6.6 s of tokens
+  19.548s  fs   cmd start    /bin/zsh -c python3 -m unittest 2>&1 | tail -5   [dispatch 37 ms]
```

(That excerpt shows the format with illustrative numbers. Real values come from the first batch.)

## 4. Action features (approved vs unapproved)

These are computed per session, but they describe **what was done**, not who did it. They drive the second model head and the rule baseline.

| ID | Feature | What it measures |
|---|---|---|
| A1 | `act_sensitive_read` | Opens of credential-shaped paths (`.env`, `id_*`, `.aws/credentials`, keychains, canary files) |
| A2 | `act_sensitive_read_outside_task` | Sensitive reads when the task didn't need them (the scenario declares its scope) |
| A3 | `act_out_of_scope_write` | Writes outside the workspace root |
| A4 | `act_delete_count` / `act_delete_preexisting` | Unlinks, and unlinks of files the session didn't create |
| A5 | `act_truncate_log` | Truncation or overwrite of `*.log` or shell history files |
| A6 | `act_persistence_write` | Writes into `LaunchAgents`/`LaunchDaemons`, shell rc files, crontab, or a `btm_launch_item_add` event |
| A7 | `act_exec_downloaded` | Executes a file that was created by the same session after network activity, or `curl … \| sh` |
| A8 | `act_chmod_exec` | `chmod +x` (setmode) on a newly created file |
| A9 | `act_sensitive_then_egress` | Non-LLM upload within 30 s after a sensitive read (exfiltration) |
| A10 | `act_priv_escalation` | `sudo`, `su`, setuid events |
| A11 | `act_collect_file` | Creates a new file after reading two or more sensitive files (credential staging) |

## 5. Labels

| Label | Values | Source |
|---|---|---|
| `actor` | `claude_code`, `codex`, `human`, `script` | Who the runner launched |
| `is_agent` | `1` / `0` | `claude_code`, `codex` → 1 |
| `action_label` | `approved`, `unapproved` | Scenario file |
| `action_category` | e.g. `exfiltration`, `persistence` | Scenario file |
| `outcome` | `completed`, `not_completed`, `refused` | Scenario checks run after the session |

`script` is a non-AI automation baseline: the same scenario done by a shell script. Without it, the model learns "automated vs human" instead of "agent vs everything else."

## 6. What the feasibility study answers

1. **Agent vs human**, using network-only, fs-only, and both.
2. **Claude vs Codex** (attribution).
3. **Approved vs unapproved** actions.
4. Each of the above **with marker features removed**. If accuracy holds, the signal is behavioral and can generalize to unknown agents.
5. The **timing module on its own**, as a separate detector.
