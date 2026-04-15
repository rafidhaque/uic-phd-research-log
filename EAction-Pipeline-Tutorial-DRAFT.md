# EAction Pipeline Tutorial (DRAFT — needs Carlo's corrections)

> Written by Rafid based on meeting notes and codebase exploration.
> Integrated missing information - CFV, 4/14/2026

---

## Overview

The pipeline has two phases:

1. **Capture phase** — run a GitHub Actions workflow while eaudit records every syscall into a `.out` binary trace file
2. **Detection phase** — replay the `.out` trace through the compiled E* policy (`workflowDetect.ese`) which fires alarms if attack patterns are found

---

## Prerequisites

- Linux machine (Ubuntu 24.04, kernel 6.14)
- BCC toolkit installed (required by eaudit — see `eaudit/INSTALL.md`)
- GitHub CLI (`gh`) authenticated to the `cfvescovo/eactions` repo
- GitHub Actions self-hosted runner installed at `/home/github-runner/actions-runner`
- Working directory: `/path/to/nhost/` (the folder containing `eaudit/`, `Host/`, `workflowCapture.sh`)

To verify BCC is working:
```bash
cd eaudit/
make all
./ecapd
# Should print: "Logprinter: 0M records, average size 8" after ~10 seconds
# If not, run: ./bcc_install.sh
```

---

## Part 1 — Capturing Traces (Automated)

Carlo's script `workflowCapture.sh` automates the full capture loop for all 8 workflows.

### Run it:
```bash
cd /path/to/nhost/
bash workflowCapture.sh
```

### What it does for each workflow:
1. Checks if `<workflow-name>.out` already exists — skips if so
2. Starts `eauditd` in the background, saving output to `<workflow-name>.out`
3. Waits until eauditd prints `"Logprinter"` (meaning it's ready to capture)
4. Starts the GitHub Actions runner (`Runner.Listener`)
5. Reruns the workflow via `gh run rerun`
6. Watches until the workflow completes
7. Stops the runner and stops eauditd
8. Saves the capture file

### Output:
After running, you should see 8 `.out` files (currently stored in `Host/actions/runs/`):
```
attack-exfil-demo.out
attack-lotl-demo.out
attack-malware-demo.out
attack-solarwinds-demo.out
benign-exfil-demo.out
benign-lotl-demo.out
benign-malware-demo.out
benign-solarwinds-demo.out
```

### If you need to recapture a single workflow:
Delete the existing `.out` file, then run the script again — it skips workflows that already have a `.out`.
```bash
rm Host/actions/runs/attack-exfil-demo.out
bash workflowCapture.sh
```

---

## Part 2 — Running Detection

The compiled detection policy is at `Host/actions/workflowDetect.ese`.

The policy was compiled from `Host/actions/workflowDetect.es` using the E* compiler (`esc/esc`).

Compile command: `./esbuild actions/workflowDetect.es actions/workflowDetect.C` (from the Host folder)

### Run detection against a capture file:

```bash
cd Host/actions/
./workflowDetect.ese -r runs/attack-exfil-demo.out
```

### Expected output:

For **attack** traces, you should see an alarm like:
```
<timestamp>: Alarm: SensitiveExfiltration: Object IP4:<attacker-ip> Subject pid=<pid> curl ...
```

For **benign** traces, you should see **no alarm output**.

---

## Part 3 — Recompiling the Detection Policy (if you edit the rules)

If you modify `workflowDetect.es` and need to recompile:

`./esbuild actions/workflowDetect.es actions/workflowDetect.C` (from the Host folder)

---

## Part 4 — Understanding the Detection Rules

The detection logic is in `Host/actions/workflowDetect.es`. It has 4 modules:

| Module | What it does |
|--------|-------------|
| `initWorkflowSpecific` | Tags pre-existing files containing `token=` as `conf(SECRET)` |
| `initRuntimeTokenObjects` | Tags newly created objects with `token=` in their name as `conf(SECRET)` |
| `initRunnerTokenSubjects` | Tags runner processes (`Runner.Worker`, `Runner.Listener`, etc.) as `conf(SECRET)` if they have `token=` in their args |
| `detectExfiltration` | Fires alarm when a `conf(SECRET)` process writes to a non-local, non-private external IP from within a GitHub runner context |

**The alarm fires when ALL of these are true:**
- The destination is a network socket (IP4/IP6/SOCKADDR)
- The destination is NOT localhost (127.x, ::1)
- The destination is NOT a private network (10.x, 192.168.x, 172.16-31.x)
- The process is in a GitHub runner context (path contains `actions-runner`, `Runner.Worker`, etc.)
- The process has `conf(SECRET)` tag

---

## Part 5 — Full End-to-End Test (Sanity Check)

To verify the pipeline is working correctly from scratch:

1. Capture all 8 traces:
   ```bash
   bash workflowCapture.sh
   ```

2. Run detection on each trace:
   ```bash
   # Should produce alarms:
   ./workflowDetect.ese -r runs/attack-exfil-demo.out
   ./workflowDetect.ese -r runs/attack-lotl-demo.out
   ./workflowDetect.ese -r runs/attack-malware-demo.out
   ./workflowDetect.ese -r runs/attack-solarwinds-demo.out

   # Should produce NO alarms:
   ./workflowDetect.ese -r runs/benign-exfil-demo.out
   ./workflowDetect.ese -r runs/benign-lotl-demo.out
   ./workflowDetect.ese -r runs/benign-malware-demo.out
   ./workflowDetect.ese -r runs/benign-solarwinds-demo.out
   ```

3. Verify results match expectations (alarm on attack, silence on benign).

---

## Common Issues

In normal conditions, as of 4/14/2026, there should be no issues with traces collection in our Proxmox VM environment.
I'm leaving the following list here for future reference.
- eauditd fails to start → check BCC installation, run `./bcc_install.sh` (DO NOT RUN ON CURRENT PROXMOX ENV; THIS SHOULD NOT HAPPEN. IF IT DOES, INFORM CARLO ASAP)
- Runner fails to start: never happened to me, maybe something is wrong with the service? Check status with svc.sh status or using systemctl
- `gh run rerun` fails → make sure `gh` is authenticated: `gh auth status`
- `.out` file is empty → wait, eaudit is still working

It's much more common for the detection part to have issues, especially if investigating traces with fql (i.e. through fqsh). Unfortunately, there are no specific fixes: most of the problems are caused by incompatibilities between Host/eaudit and the old fql code.

---

## VM Access (Proxmox)

The pipeline runs on Carlo's Proxmox VM. To access it:

1. Connect to WireGuard VPN using config: `~/Downloads/rafidsisl.conf`
   ```bash
   sudo wg-quick up ~/Downloads/rafidsisl.conf
   ```
2. Open Proxmox web UI: `131.193.36.4:8006`
3. Login to VM 104, username: `rafid`, password: `consumer`
4. The nhost folder is at: `~/Desktop/Marco/nhost/`

Use VSCode Remote SSH plugin whenever possible, it's generally more performant and convenient than using Proxmox's own web UI.

---

*Last updated: 2026-04-14 | Send corrections to Rafid*
