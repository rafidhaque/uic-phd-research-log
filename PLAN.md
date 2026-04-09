# ProvAction — Research Project Plan
> Last updated: 2026-04-08 (after Carlo meeting + workflow development)
> To resume: tell Claude "read PLAN.md and continue the project"

---

## How Claude Will Work With Rafid (Collaboration Protocol)

Prof. Venkat has explicitly criticized AI-generated content. Rafid must understand and own the work, not just paste outputs. This section defines how Claude should behave in this project.

### The Rules

**1. Ask before answering.**
If Rafid asks a conceptual question (e.g., "what is the abstract pattern?"), Claude asks "what do you think it is first?" before explaining. This is the Socratic method. The goal is to find out where Rafid's understanding breaks down and fix that, not to hand him the answer.

**2. For things Rafid must author (E* rules, emails, presentations, documents) — give feedback, not drafts.**
Claude reads what Rafid wrote, points out what's wrong or incomplete, and explains why. Rafid rewrites. Repeat. This is how the E* rules in secret_exfit.es.txt were built — Rafid wrote every line himself.

**3. For infrastructure/code that nobody cares who wrote (GitHub Actions YAML, debug commands, CI fixes) — Claude can just do it.**
The professor doesn't care who wrote the workflow YAML. He cares who understands the research.

**4. If Rafid is completely stuck and has genuinely tried — give a hint, not the answer.**
A hint is: "think about what happens to the integrity tag when a third-party process reads a file." Not: "the pattern is low-integrity process reads high-confidentiality file."

**5. After explaining something, ask Rafid to rephrase it in his own words.**
If he can rephrase it correctly, he understood it. If not, the explanation didn't land and Claude tries again differently.

**6. Never write something Rafid will say out loud to the professor.**
Talking points, meeting responses, quiz answers — Claude can quiz Rafid and give feedback on his answers, but Rafid produces them.

**7. When Rafid asks Claude to "write the email" or "write the document" — ask him to draft it first.**
Then Claude reviews and gives specific feedback. Exception: purely logistical/administrative emails where content doesn't matter.

### Why This Matters
- Professor Venkat will quiz Rafid in meetings. If Rafid doesn't understand it, he'll get caught.
- The professor specifically said "I can tell when it's AI-generated." He's watching.
- Rafid's long-term goal is to do research, not to be good at prompting Claude.

---

## What This Project Is

**ProvAction** — Runtime security monitoring for GitHub Actions using kernel-level provenance tracing.

The core idea: GitHub Actions workflows are blind to what third-party actions actually do at runtime. We use eaudit (eBPF-based syscall tracer) to capture a provenance graph of everything that happens during a workflow run, then use that graph to detect or discover attacks.

**Lab**: UIC (University of Illinois Chicago)
**Student**: MdRafid Haque (Rafid)
**Advisors**: Prof. Venkat, Prof. Rigel Gjomemo
**Collaborator**: Carlo Federico Vescovo (lab mate, masters student, manages Proxmox VM)
**External**: Prof. Sekar + Sagar Mishra (Stony Brook, original eaudit authors)

---

## The Research Question (clarified in 3rd meeting, 2026-03-26)

**Two-part project** (clarified by Prof. Venkat):

### Part 1 — Vulnerability Analysis & Attack Enumeration (main current focus)
Given any GitHub Actions workflow:
1. Run it (benign) → capture provenance graph
2. Extend that graph with "special/wildcard edges" representing where attacks *could* connect
3. Write E* patterns that match **prefixes** of the 4 attack patterns in the benign graph
4. For each prefix match found → **generate a third-party action script** (suffix) that completes the attack
5. The suffix + existing workflow together = concrete, realized attack
6. Run the workflow again with that malicious third-party action → verify the attack manifests in the new provenance graph

**Key constraint**: The only thing you control is the third-party action script. You cannot change the workflow or repo code.

**Key insight on labels**: Patterns are expressed via integrity/confidentiality tags, NOT specific filenames.
- Source = any process that acquired low-integrity tag (came from third-party)
- Sink = any high-confidentiality file / low-confidentiality write channel
- E.g., exfiltration = low-integrity process reads high-confidentiality file → writes to external socket

**Attack ordering**: Some attacks are preconditions to others. If no direct exfiltration path exists, you may first need to inject low-integrity files that open sockets, then exfiltrate.

### Part 2 — Monitoring & Prevention (what eaudit/E* does)
- Catch attacks before the suffix actions execute
- eaudit traces + E* detection rules
- This is built on top of Part 1's attack traces

**The overall system goal**: Given any repository, automatically synthesize custom third-party actions that demonstrate exactly how it is vulnerable.

### Three intermediate results toward Part 1:
1. Generation of **attack traces** (provenance graphs with attack activity)
2. Generation of **attack scripts** (the third-party action code)
3. **Automated testing** of attack scripts + traces for any workflow config

### Dataset goal:
Collect real GitHub repos with workflows → test on diverse real-world configs (not just provaction's own)

---

## Current Research Status

### What's Done ✅
- eaudit pipeline working on GitHub Actions (Ubuntu 24.04, kernel 6.14)
- Composite action builds BCC from source, runs ecapd, captures trace
- Three attack simulations running in CI and captured in traces:
  1. Secret Exfiltration (`/proc/self/environ` → outbound HTTP)
  2. Living off the Land (curl → write `/tmp` → execute)
  3. Build Artifact Poisoning (two steps, different ancestry, overwrite same file)
- Trace artifacts uploaded after each run (`eaudit-trace.out`, `eaudit-trace.txt`)
- Attack model document: `/Users/user/Downloads/attack_model.tex`
- E* detection rules written by Rafid: `/Users/user/Documents/secret_exfit.es.txt`
- Carlo got full pipeline working on VM (eaudit → eConsumer → Host → dump.txt)

### What's In Progress 🔄
- Sagar's updated eConsumer received by Rigel — Carlo currently working on integrating it into VM
- Self-hosted runner setup (Rafid working on this)
- Abstract pattern formulation being discussed with Prof. Venkat via Slack

### What's Blocked ⏳
- Clean end-to-end pipeline (eaudit → eConsumer online mode → Host) waiting on Sagar
- Running our GitHub Actions attack traces through the full Host pipeline (waiting on above)

---

## The Full Technical Pipeline

```
GitHub Actions Runner
  ecapd (captures syscalls)
    ↓ online mode (NOT pipe, NOT offline file)
  eConsumer (translates syscalls → provenance events)
    ↓
  Host (builds provenance graph, runs E* rules)
    ↓
  dump.txt / provenance graph
    ↓
  Graph search for attack path patterns
    ↓
  Attack path report
```

**Important**: Prof. Sekar warned NEVER use pipes between ecapd and eConsumer — causes data loss. Online mode is the correct approach. Sagar is implementing it.

---

## Key Technical Concepts

### eaudit
- eBPF-based syscall tracer from Stony Brook Secure Systems Lab
- `ecapd` = bash wrapper around `eauditd.py`, captures syscalls to binary `test.out`
- `./eaudit -I test.out -P test.txt` converts binary to human-readable
- Carlos's fork (cfvescovo/eaudit) fixes Ubuntu 24.04 compatibility

### eConsumer
- Reads eaudit binary trace, translates syscalls into provenance events
- Feeds into Host runtime
- Source: `/Users/user/Downloads/eaudit-old/eaudit/eConsumer.C`
- Online mode = eConsumer runs alongside eaudit (correct)
- Offline mode = processes saved file after the fact (loses file permissions, connection metadata)

### Host
- Builds the provenance graph from eConsumer events
- Maintains nodes (subjects=processes, objects=files/IPs) and edges (read/write/exec/connect)
- Applies tags, propagates taint, runs E* rules
- Source: `/Users/user/Downloads/nhost/Host/`

### E* Language
- Rule-based event monitoring language
- Syntax: `event_pattern | condition --> { action }`
- Tags: integrity (Untrusted/AuthBenign/Invulnerable) + confidentiality (Public/Private/Secret)
- Tag propagation = taint tracking through the graph
- Compiler (esc): `/Users/user/Downloads/nhost/esc/esc`
- Rafid's detection rules: `/Users/user/Documents/secret_exfit.es.txt`

### Provenance Graph
- Nodes: subjects (processes) and objects (files, IPs)
- Edges: syscall events (open, read, write, execve, connect, clone)
- Tags propagate: if process reads UNTRUSTED file → process becomes UNTRUSTED
- Carlo's test dump: `/Users/user/Downloads/dump.txt`

---

## E* Detection Rules (written by Rafid)

Three modules in `/Users/user/Documents/secret_exfit.es.txt`:

**Module 1 — Secret Exfiltration**
- Watch: process reads `/proc/*/environ` → remember its PID
- Alarm: same PID writes to an external IP

**Module 2 — Living off the Land**
- Watch: any write to `/tmp/*` → remember filename
- Alarm: any execve of that exact filename

**Module 3 — Build Artifact Poisoning**
- Watch: first write to `*/dist/binary` → remember PID and filename
- Alarm: different PID writes to same file (firstWriterPID != 0 guard)
- Known limitation: single variable, not dict — only tracks last writer. Dict fix known.

---

## VM / Infrastructure

**Proxmox VM** (managed by Carlo):
- Access: WireGuard VPN → `131.193.36.4:8006` (Proxmox web UI)
- VM 104, username: `rafid`, VM desktop password: `consumer`
- WireGuard config: `/Users/user/Downloads/rafidsisl.conf`
- Folder structure on VM: `~/Desktop/Marco/nhost/` contains `Host/`, `esc/`
- eConsumer should go at: `~/Desktop/Marco/nhost/src/Consumers/eaudit/`
- File transfer tool: `croc` (brew install croc)

**GitHub Actions pipeline**:
- Repo: `/Users/user/New/provaction/`
- Main workflow: `.github/workflows/poc-trace.yml`
- eaudit action: `.github/actions/eaudit-monitor/action.yml`
- Artifacts uploaded after each run: `eaudit-trace.out` + `eaudit-trace.txt`

---

## Professor's Key Instructions (from meetings)

1. **Work offline first** — get pipeline working on VM, then worry about CI integration
2. **Don't call it pattern matching** — call it "reasoning with provenance" (tag propagation, information flow)
3. **No Python reimplementation** — use the C++ Host codebase, don't replicate 2 years of work
4. **Self-hosted runner = demo platform** — primary threat model is GitHub-hosted runners
5. **Systematic not ad hoc** — attacks as graph search problem, not a list from papers
6. **Label AI usage** — annotate documents with what was AI-generated vs your own thinking
7. **The research question is open** — original problem solving required on the abstraction/formulation

---

## Attack Scenarios (7-8 from literature)

The three simulated in CI cover the main patterns. Full table of 7-8 attack vectors exists in Rafid's notes/presentation to professor. All reduce to 4 abstract source→sink path patterns:

1. **Exfiltration**: third-party process reads sensitive object → writes to external IP
2. **Artifact Poisoning**: third-party process writes to object defined in workflow config as deployable
3. **Payload Download and Execution**: third-party reads from external IP → writes file → file executed by another process (high false positive risk)
4. **Persistence** (self-hosted only): third-party writes to cache/work folder to survive across runs

**Sinks** (from workflow config + environment):
- Secrets: env variables, token files
- Build artifacts: whatever workflow config defines as deployed/uploaded
- Persistent storage: cache, work folder (self-hosted runners only)

**Sources**: always third-party GitHub Action processes

---

## Pending Questions / Open Problems

1. **Abstract pattern formulation** — what stays the same across attack variants? (the active research question)
2. **Graph construction** — what graph do you build that, when searched, reveals novel attack paths?
3. **Self-hosted runner setup** — Rafid setting up on personal machine
4. **Online eConsumer** — waiting on Sagar to commit to SVN
5. **Running attack traces through Host** — blocked on above
6. **dev/shm** — Rafid should know what this is (came up in meeting, professor tested him on it)

---

## Rafid's 3 Buckets (set by Prof. Venkat in 4th meeting)

**Bucket 1 — Realistic Benchmarks** (impacts final results)
- Create benign workflow(s) + attack workflow variants
- These are the test inputs for the whole pipeline
- Prof. Venkat: "creating the workflow is less than a one-hour job"

**Bucket 2 — Learning Task** (internal, not in final results)
- Understand how GitHub Actions steps map to eaudit events
- One-to-one: what does `actions/checkout` look like in the audit log?
- Need this before writing meaningful E* rules

**Bucket 3 — E* Detection Rules** (core deliverable)
- Write E* rules that capture attack patterns with proper tag initialization
- Must print "attack pattern detected" when attack workflow runs
- Capture both attack AND benign patterns (for whitelisting)

**Minimum viable demo (target: next week)**
- One benign + 1-2 attack workflows running through eaudit pipeline
- E* rules that fire on the attack and stay silent on benign
- Output: alert + trace of events that triggered it

---

## Novel Research Direction (from Rigel, 4th meeting)

**Per-action graph coloring** — instead of binary Unknown/Benign tagging, assign each third-party action its **own unique tag ID**. Every entity (process, file, socket) spawned from that action inherits that specific tag. This enables:
- Backtracking exactly which action caused which behavior
- Finer-grained detection than Sleuth's binary trust model
- Carlo needs to make tag creation dynamic in Host codebase

Rigel said: *"that would be novel."* This is a potential research contribution.

**Check Slack** — Rigel shared the old tag design document in the Slack channel (with Venkat, Carlo, Rafid, Rigel). Read it.

---

## Attack Detection Policies (written by Rafid, 2026-04-02)

Full LaTeX document at: `/Users/user/uic-phd-research-log/01-Research-Projects/attack-policies.tex`

Summary:
1. **Exfiltration**: Unknown-tagged process reads Secret/Sensitive file → writes to non-whitelisted network destination → alarm
2. **Malware Download & Execution**: Unknown process downloads file → payload tagged Unknown → any process executes it → alarm
3. **SolarWinds**: First writer finishes writing deployment binary → Unknown-tagged second process writes same binary → alarm
4. **LotL**: Third-party action creates/modifies file → file tagged Unknown → benign process reads/executes it → inherits Unknown tag → alarm

Tags used: t-tags (Benign-Authentic / Benign / Unknown) + c-tags (Secret / Sensitive / Private / Public)
Initial tags sourced from: workflow YAML (third-party actions → Unknown, secrets/env vars → Secret/Sensitive)

---

## Demo Workflows (Carlo's repo: cfvescovo/eactions)

### Benign Workflows ✅ (all pushed)
- `benign-exfil-demo.yml` → uses `system-status-reporter` action (reads SECRET_TOKEN, curls to httpbin)
- `benign-malware-demo.yml` → uses `azure/setup-helm@v4` (downloads + installs Helm)
- `benign-lotl-demo.yml` → uses `cmake-builder` action (cmake + make on main.c)
- `benign-solarwinds-demo.yml` → uses `solarwinds-builder` action (cmake + make on deploy.c)

### Attack Workflows 🔄 (in progress)
- Attack workflows call attack actions — workflows stay same, only action changes
- `attack-exfil-demo.yml` → calls `attack-exfil` action (IN PROGRESS — add evil curl line)
- `attack-malware-demo.yml` → calls `attack-malware` action (TODO)
- `attack-lotl-demo.yml` → calls `attack-lotl` action (TODO)
- `attack-solarwinds-demo.yml` → calls `attack-solarwinds` action (TODO)

### Key Research Finding (from Carlo meeting 2026-04-08)
Benign and malicious exfiltration are **behaviorally identical** in the provenance graph — same pattern, only destination differs. Whitelisting is not the answer (endless list, Pastebin problem). This is an open research problem. Dynamic per-action tagging (Rigel's idea) may help distinguish them.

### C files in repo root
- `main.c` → hello world (used by cmake-builder / LotL demo)
- `deploy.c` → "Deploying..." (used by solarwinds-builder)
- `CMakeLists.txt` → builds both `hello` and `deploy` executables

---

## Next Actions

### IMMEDIATE
- [ ] Finish `attack-exfil/action.yml` — add evil curl line (Rafid writing this)
- [ ] Write `attack-malware/action.yml` — same as tool-installer but downloads from malicious URL
- [ ] Write `attack-lotl/action.yml` — same as cmake-builder but also writes malicious file that make executes
- [ ] Write `attack-solarwinds/action.yml` — same as solarwinds-builder but second process modifies the binary after build
- [ ] Push all attack actions
- [ ] Carlo runs benign workflows through eaudit pipeline and records provenance graphs

### WHEN PIPELINE READY
- [ ] Run attack workflows through eaudit → compare graphs with benign
- [ ] Update E* rules with tag-based policies (replace filename-based rules in secret_exfit.es.txt)
- [ ] Verify: alarm fires on attack workflow, stays silent on benign

### OTHER ONGOING
- [ ] Check Slack for tag design document Rigel shared
- [ ] Read about DFQL/FQL query language in Host codebase (Carlo knows this well)
- [ ] Learn what dev/shm is (professor tested Rafid on this, didn't know)
- [ ] Next meeting: Friday 10 AM (moved from original time)

---

## People & Contacts

| Person | Role | Contact |
|--------|------|---------|
| Prof. Venkat | Primary advisor UIC | Slack/email |
| Rigel Gjomemo | Research Scientist UIC | rgjome1@uic.edu |
| Carlo Federico Vescovo | Lab mate, VM admin | Slack (cvesc@uic.edu) |
| Sagar Mishra | Stony Brook, eConsumer dev | sagar.mishra.ntc@gmail.com |
| Prof. Sekar | Stony Brook, eaudit author | sekar@cs.stonybrook.edu |
