# Disposable macOS VMs (phase 2)

The feasibility demo runs on the host: every run gets a fresh copy of the workspace under
`~/UmbraLab/sandboxes/`, and the sensor follows only that run's process tree. That's
enough to answer "can we tell them apart?", and it keeps setup to zero.

Move to VMs when you need any of these:

- **Real unapproved actions.** Write to the real `~/Library/LaunchAgents`, read the real
  `~/.ssh`, run `launchctl`, use `sudo`. On the host these are simulated inside `home_sim/`.
- **A clean baseline.** No browser, Slack or Docker noise in the network capture.
- **Parallel runs.** One run per VM.

## Recommended: Tart (Apple Virtualization.framework)

```bash
brew install cirruslabs/cli/tart
tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest umbra-golden
tart run umbra-golden            # first boot: do the one-time setup below, then shut down
```

One-time setup inside the golden image (this part can't be scripted, because TCC needs a click):

1. System Settings > Privacy & Security > Full Disk Access: add Terminal (or `sshd-keygen-wrapper` if you drive it over SSH), so `eslogger` can run.
2. Install `claude`, `codex`, `uv`, and Wireshark's `tshark`, and sign in to both agents.
3. Clone this repo and run `uv sync` in `training/`.
4. Enable passwordless sudo for the `sensor.py` path only:
   `echo "admin ALL=(root) NOPASSWD: /path/to/.venv/bin/python -I /path/to/sensor.py *" | sudo tee /etc/sudoers.d/umbra`

Then each run becomes:

```bash
tart clone umbra-golden run-$ID && tart run --no-graphics run-$ID &
ssh admin@$(tart ip run-$ID) "cd Umbra/training && uv run umbra-train run --actor codex --scenario u03"
scp -r admin@$(tart ip run-$ID):Umbra/training/data/runs/ ../data/runs/
tart delete run-$ID
```

Limits to plan around:

- Apple's license allows **two macOS VMs at a time** per Mac.
- Each clone uses about 25–50 GB until it's deleted. Your disk had about 61 GB free when this was written.
- Agent sign-in tokens live in the golden image, so treat the image as a secret.
