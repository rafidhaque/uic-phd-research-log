# EAction — Research Project Plan
> Last updated: 2026-04-23 (meetings 9-12 + Carlo Meeting 3 processed)
> To resume: tell Claude "read PLAN.md and continue the project"

---

## Daily Venkat Update Protocol

Rafid sends a detailed Slack text to Venkat EVERY day with progress, thought process, and questions. This is important because:
- Both Rafid and Venkat communicate better in text than speech (neither's first language is English)
- Venkat is less frustrated in meetings when he's already seen progress via text
- Writing forces Rafid to clarify his own thinking
- Claude should always help prepare this daily message as part of each session's output

**Format:** What I worked on today → What I figured out → What I'm stuck on → Plan for tomorrow

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

**7. Never include "Co-Authored-By: Claude" in git commit messages.**
Commits should appear as Rafid's alone. Do not add any Claude co-author trailer to commit messages.

**7. When Rafid asks Claude to "write the email" or "write the document" — ask him to draft it first.**
Then Claude reviews and gives specific feedback. Exception: purely logistical/administrative emails where content doesn't matter.

### Why This Matters
- Professor Venkat will quiz Rafid in meetings. If Rafid doesn't understand it, he'll get caught.
- The professor specifically said "I can tell when it's AI-generated." He's watching.
- Rafid's long-term goal is to do research, not to be good at prompting Claude.

---

## THE CORE RESEARCH PROBLEM (The Hard Part)

This section describes the fundamental challenge we are stuck on. It is written for someone (e.g., Claude Opus) who needs full context to help think through a solution.

### Background: What is a Provenance Graph?

A provenance graph is a directed graph built from kernel-level syscall events (captured by eaudit, an eBPF tracer). It has:
- **Nodes**: subjects (processes) and objects (files, network IPs)
- **Edges**: syscall events — read, write, execve, connect, open, clone

Example: a process reads a file → there is a directed edge from the file node to the process node. A process writes a file → directed edge from process to file. A process connects to an IP → directed edge from process to IP node.

Tags are attached to nodes/edges:
- **Integrity tags (t-tags)**: `untrusted`, `benign`, `invulnerable` — where did the content come from? Is the process trustworthy?
- **Confidentiality tags (c-tags)**: `secret`, `sensitive`, `private`, `public` — how sensitive is the data?

Tag initialization (from the workflow YAML):
- Secrets / environment variables → `conf(secret)` or `conf(sensitive)`
- Third-party GitHub Actions (actions not owned by the repo) → `integ(untrusted)`
- First-party repo code, OS binaries → `integ(benign)` or `integ(invulnerable)`

Tag propagation (taint tracking):
- If an untrusted process reads a file → that file becomes tainted
- If a process reads a secret file → the process output inherits conf(secret)
- Conservative: output inherits the lowest integrity tag and highest confidentiality tag of all inputs

### The 4 Attack Patterns We Are Studying

All attacks are caused by malicious **third-party GitHub Actions** — external code plugged into a workflow via `uses: some-third-party/action@v1`. The repo owner did not write this code. It runs inside the CI pipeline with access to secrets and the build environment.

**Attack 1 — Secret Exfiltration**:
The third-party action reads a secret (e.g., `$SECRET_TOKEN` from env) and sends it to an external URL controlled by the attacker.
- Provenance pattern: `[third-party process: untrusted]` → reads `[secret env var: conf(secret)]` → connects to `[attacker IP]` → writes secret data

**Attack 2 — Malware Download & Execution**:
The third-party action downloads a script from an attacker-controlled URL and executes it.
- Provenance pattern: `[third-party process: untrusted]` → connects to `[attacker IP]` → writes `[/tmp/malware.sh]` → `[bash]` executes `/tmp/malware.sh`
- The downloaded file inherits the `untrusted` tag because it came from an untrusted process
- An benign process (bash) then executes an untrusted file

**Attack 3 — SolarWinds (Build Artifact Poisoning)**:
The third-party action modifies source code before compilation, so the malicious code gets baked into the build artifact. The artifact looks legitimate (built by the official build system) but is compromised.
- Provenance pattern: `[third-party process: untrusted]` → writes to `[deploy.c]` → `[make/gcc: benign]` reads modified `deploy.c` → writes `[deploy binary]` → the binary is now tainted

**Attack 4 — Living off the Land (LotL)**:
The third-party action creates a malicious script using only tools already present on the system (echo, bash, curl) — no external download. The script is written inline and then executed.
- Provenance pattern: `[third-party process: untrusted]` → uses echo (built-in bash) to write `[/tmp/evil.sh: untrusted]` → `[bash: benign]` executes untrusted script → bash reads secret env → connects to attacker IP

### THE HARD PROBLEM: Benign vs Malicious Look Identical

**The fundamental challenge**: For most of these attacks, the provenance graph pattern of the **benign version** and the **malicious version** is structurally identical. Only the destination or content differs — and the provenance graph does not capture content.

**Exfiltration — the clearest example of the problem**:

*Benign workflow*: A legitimate status reporter action reads `$SECRET_TOKEN` and sends it to `https://httpbin.org/post` (a monitoring service). This is the intended behavior.

*Malicious workflow*: The same action also sends `$SECRET_TOKEN` to `https://attacker.com/exfil`.

In the provenance graph, **both look like**:
```
[third-party process: untrusted] → reads [SECRET_TOKEN: conf(secret)] → connect([some IP]) → writes secret data
```

The structure is: untrusted process reads secret → writes to network. Both benign and malicious do this. The graph cannot tell them apart because:
1. It doesn't capture the actual URL value (only that a connection happened)
2. Even if it did capture the URL, you'd need a whitelist of "good" URLs — which is an infinite and unmaintainable list
3. The "Pastebin problem": an attacker can always use a legitimate service (pastebin, webhook.site, requestbin) as a relay

**Tag-based detection also fails here**:
A tag-based rule saying "alarm if untrusted process reads secret and writes to network" would fire on BOTH the benign and malicious exfil. 100% false positive rate on legitimate CI pipelines that need to use secrets to authenticate to external services.

**LotL — a secondary version of the problem**:
Benign: cmake + make builds a project. A build tool is a "benign" process that reads source files and writes a binary.
Malicious (LotL): the malicious action writes a script to /tmp using echo, bash executes it. In the graph, this looks like: bash (benign) writes a file, bash executes it. But bash does this all the time legitimately.

**Malware — partially detectable but with false positives**:
"Untrusted process downloads file → executes it" is detectable, but many legitimate actions do exactly this (e.g., installing tools via curl | bash, which is extremely common in CI).

**SolarWinds — most detectable**:
"A second process modifies the same build artifact after the first process wrote it" is a cleaner signal. But what if the build legitimately involves multiple steps that write to the same file?

### Current State of Detection

The E* rules that currently exist (`secret_exfit.es.txt`) are **filename-based**, not tag-based:
- Watch process reads `/proc/*/environ` → watch if it then writes to external IP
- Watch write to `/tmp/*` → alarm if same file gets executed
- Watch first write to `*/dist/binary` → alarm if different process writes same file

These are toy rules written before we understood the tag system. They need to be completely rewritten to use `integ()` and `conf()` tags. But even with tags, the exfiltration problem remains: the tag-based rule fires on both benign and malicious.

### Potential Directions Being Considered

**Direction 1 — Per-action graph coloring (Rigel's idea)**:
Instead of a binary `untrusted/benign` tag, assign each third-party action its own unique integer tag ID using `def(i)`. Every entity produced by that action inherits `use(i)`. This enables pinning behavior to a specific action. If `actions/checkout` (trusted, open source) is assigned `def(1)` and a new unknown third-party action is assigned `def(2)`, you can distinguish their outputs even if both are "untrusted." This is more fine-grained but doesn't solve the "benign exfil" problem by itself.

**Direction 2 — Destination-aware provenance**:
Capture not just that a connection happened, but to what class of destination (known-good, unknown, known-bad). This requires a threat intelligence feed or a policy about what external destinations are acceptable for a given repo/workflow. Complex and brittle.

**Direction 3 — Behavioral anomaly (not pure provenance)**:
If the benign workflow only ever contacts one URL but the attack version contacts two, the difference is detectable as an anomaly — even if each individual connection looks benign. This requires a baseline of expected behavior.

**Direction 4 — Workflow-aware policies**:
Parse the workflow YAML to extract the declared behavior (what secrets the workflow says it uses, what URLs it says it contacts), then alarm on any behavior that exceeds the declared scope. E.g., if the workflow only declares `report_url` as an output destination, any other outbound connection from the same secret-reading process is an anomaly.

### What We Need Help Thinking Through

1. Is there a principled way to distinguish benign from malicious exfiltration using only provenance graph information (no content inspection, no URL whitelisting)?
2. Can the tag system from Rigel's `tagnew.pdf` (def/use IDs, tagOps like merge/concat) help solve this?
3. What E* rules should we write for each of the 4 attacks that have acceptable false positive rates?
4. How does the academic literature handle this "intended vs unintended information flow" distinction?

---

## What This Project Is

**EAction** — Runtime security monitoring for GitHub Actions using kernel-level provenance tracing.

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

## 9th Meeting Outcomes (2026-04-22, group meeting with Venkat, Rigel, Carlo)

### Overall Tone
Venkat was direct and critical of Rafid's sub-questions. Teaching moment — not angry, but firm. Carlo and Rigel contributed ideas for a potential third research component.

### Venkat's Core Critique of RQ Sub-Questions
Venkat's central point, repeated multiple ways throughout the meeting:
- The sub-questions Rafid submitted describe work that is **already known from prior papers** (Sleuth, Holmes, etc.)
- You cannot instantiate existing techniques in a new context and call it novel research
- Each bullet must describe work whose answer is **genuinely unknown** and requires investigation
- Example: "How to differentiate benign from malicious?" → Venkat said tag propagation already solves this. Not a research question.

### Venkat's Process for Writing Research Questions
**Write bullets first, questions second.**
1. List the specific novel work you will do under a broad area (e.g., "attack detection")
2. Make sure each bullet is genuinely new — not found in Sleuth, Holmes, or any prior paper
3. Once bullets make sense as individual questions, summarize them into one high-level research question on top
4. Do NOT write the question first and then struggle to find what goes under it

### RQ1 Sub-Questions — Approved
Venkat confirmed his three sub-questions for RQ1 are correct:
- Baseline policy = what applies to ALL workflows (e.g., don't compromise log files)
- Project-specific policy = whitelisting trusted URLs, marking secrets, developer annotations
- These two get synthesized into a monitor for runtime checking

### RQ2 Sub-Questions — Rejected, Need Full Rework
Venkat did not review RQ2 in detail because the bullets were not on target. He said: "I am not even looking at what is there in RQ2" until the bullets show genuinely novel work.

### RQ3 (Forensics) — May Not Be Substantive Enough
Venkat raised the possibility of **dropping forensics as a full research section**:
> "I'm not sure that the forensic area is substantive enough at that point."

Carlo argued forensics is needed for completeness ("a complete approach from start to finish"). Venkat agreed it can be mentioned but questioned whether it's worthy of being elevated to a research area / Section 3 component. He said:
> "We need to do something new there. What is interesting about the CI-CD context where a forensic trace generation approach can actually help?"

### Carlo's Idea for Forensics (if kept)
Trace attacks back not just to nodes in the provenance graph, but to **specific instructions in the workflow YAML files or action files**. This is very specific to GitHub Actions pipelines and no existing system does this. Carlo: "I have no idea how to do this, but it would be very nice."

### Rigel's Idea: Persistence Across Runs
Attacks that persist state between different workflow runs:
- Each push triggers a new workflow run; the attack progresses a little further each time
- Must save state somehow to continue next run
- **Problem**: GitHub-hosted runners are ephemeral (fresh VM each time), but cache mechanisms exist (specific actions for build artifact caching)
- Self-hosted runners preserve the work folder across runs
- Interesting but hard to replicate on their test environment

### Venkat's Suggestion for Alternative Third Component
Instead of forensics, consider broader areas:
- Supporting essential GitHub functionality
- How monitoring remains adaptive to diverse real-world workflows
- False alarm reduction / system usability
- Scenario graph as a minor result within detection, not a standalone section

### Other CI/CD Platforms Mentioned
Carlo noted: GitLab CI, Travis, Jenkins are alternatives. Future work could generalize to other platforms. Not for now.

### Action Item
Rafid will revise research questions (especially RQ2 bullets) and discuss with Carlo before next meeting. Venkat: "Whenever you're ready, we can discuss again."

---

## Meeting 10 Outcomes (2026-04-23, in-person with Rigel + group)

### Rafid Presented the Two-Layer Idea
Rafid presented the core framing: prior provenance systems (Sleuth, Holmes) work at one layer (syscalls). EAction has two layers — the workflow YAML definition and the runtime syscall execution. The novelty is in bridging these layers.

He presented three approaches to bridge them:
1. **Timestamps** — use workflow log timestamps to partition provenance events. Dismissed: gaps in timestamps, impractical.
2. **Modify the runner** — inject markers ("Step 3 starting") into the provenance stream. Problem: can't modify GitHub-hosted runners. Could work on self-hosted, but not the primary threat model.
3. **Process tree** — watch fork/execve from the runner to infer step boundaries. Problem: Docker actions run in containers, sub-forks complicate it, optimistic to assume clean boundaries.

Rafid concluded Option 2 (runner modification) is most viable if they assume GitHub would eventually implement it, and test on self-hosted runner in the meantime.

### Rigel's Response: Two-Layer Mapping Is Trivial
Rigel compared it to **Caldera** (MITRE adversary emulation framework). In Caldera, you have ground truth commands and map syscall events back to them. Same idea: if you have the YAML file defining what runs, the mapping is straightforward.

**Key quote from Rigel**: "I'm not sure that they'll accept this as a difficult problem. As they might say, this is kind of trivial."

He also pointed out: you have the action source code, you can just look up what each step runs. There's no hidden complexity.

### Rigel Redirected Novelty
Rigel said novelty should be in **"modeling or representing what is the benign behavior"** and then **detecting deviation from it**. Not in the two-layer mapping.

### Carlo's Encoding/Embedding Idea
Carlo proposed: find a way to encode/represent the provenance graph such that:
- Minor variations between benign runs stay close (robust to noise)
- Attacks produce a large distance from the benign encoding
- Need an "embedding function that maximizes this difference"

Carlo said: **"This will be a very big novelty if we can solve this problem."**

This is a genuine graph comparison / representation learning research question. Could be a strong RQ2 sub-bullet — but it's the approach, not the question itself.

### Impact on RQ Sub-Questions
- The two-layer mapping bullet (proposed for RQ2.1) is dead — Rigel called it trivial
- The YAML trace-back forensics bullet (proposed for RQ3.1) is the same problem, also dead
- Novelty lives in baseline representation and deviation detection, not in mapping

---

## Meeting 11 Outcomes (2026-04-23, continuation of Meeting 10 discussion)

### Venkat on Baseline Policy vs Graph Learning
Venkat clarified: learning a baseline policy is **different** from learning the graph itself. The policy captures what behaviors are allowed — anything not present that looks like a violation gets flagged. Anything present in the baseline that would otherwise be a violation gets suppressed (whitelisted).

He described a simple approach: "A very simple policy where the code in the codebase is allowed to access all the files and connections it accesses, and whitelisting them, is a coarse-based policy."

### Venkat's Intuition: Simplest Approach Might Work
Run benign workflow with existing detection rules → see what alarms fire → suppress those alarms as whitelisted → then run attacks and see if remaining alarms catch them.

He said: "I didn't see any reason this was the hard bottleneck... the best way is to give us actual problems on the ground and then we can discuss."

### Carlo's Concern
Carlo raised that the simple suppression approach might not hold over time — different test runs might access different files, so the whitelist from one benign run may not cover all benign variations.

### Key Takeaway
Venkat wants to see concrete experimental results before overcomplicating the policy learning. Start simple, see where it breaks, then that tells you what the real research problems are.

---

## Carlo Meeting 3 Outcomes (2026-04-23, Rafid + Carlo in-person)

### Tag Propagation = Behavioral Analysis
Carlo confirmed: tag propagation and behavioral analysis are the same thing. Tags encode behavior. "If a process reads a secret file then writes to network — the tags capture that behavioral pattern." This means the RQ2 bullet "are there attacks beyond tag propagation?" is really asking "are there attacks beyond behavioral analysis?"

### SolarWinds Detection: Implementation Gap, Not Logic Gap
Carlo clarified: tag propagation DOES work for SolarWinds in theory. The untrusted tag from the third-party action should propagate through the file write (truncate). The miss was because eaudit doesn't capture the `truncate` syscall — an implementation gap, not a fundamental detection logic problem. Once truncate is captured, the taint chain is complete.

### Forensics: Not Novel Enough for Its Own RQ
Carlo's take: forensics (RQ3) is not substantively different from what existing provenance systems already do. Mapping provenance back to YAML is straightforward once you have the two-layer bridge. He agreed with Rigel that this isn't enough for a full research question.

### Carlo's Encoding/Embedding Idea
Carlo proposed: create a function that maps provenance graphs to numerical representations (embeddings) such that benign variations map to nearby points but attacks produce large distance. He called this "very big novelty" — learning a distance metric over provenance graphs for anomaly detection.

### Simple Suppression Approach: Start Here
Carlo agreed with Venkat: start with the simplest baseline policy approach first. Run general E* policies on benign graph → see what alarms fire → suppress those → that's your customized policy. Then run attacks against it. See what breaks, and THAT tells you what the real research problems are.

### RQ1 Evaluation Table
Carlo noted the baseline policy generation table (general policy alarms → customized alarms → attack alarms) makes more sense under RQ2 since the last columns measure detection effectiveness, not policy generation quality. Rafid will move it.

---

## Meeting 12 Outcomes (2026-04-23, group meeting with Venkat + Rigel)

### Overall Tone
Harsh. Venkat frustrated with pace of progress. Said the evaluation overview task should have taken "4-5 hours" and questioned why it's still incomplete. Pushed hard on reading papers and working more hours.

### RQ2 Sub-Questions: Still Wrong
Venkat's critique: the current RQ2 bullets are **solution-driven** not **problem-driven**. "Is tag propagation enough?" presupposes the approach. Instead: list the challenges that arise from the CI/CD security problem domain, then let the approach follow naturally.

The right process: What are the problems? → What challenges do those create? → What approaches address those challenges? Current bullets skip straight to evaluating the approach.

### Venkat's New RQ3 Idea: Contamination Analysis
Venkat proposed a new direction for RQ3: **contamination analysis**. After detecting a suspicious action:
1. Go back in time in the provenance graph
2. Find everything the suspicious action touched
3. Forward analysis to isolate all contaminated artifacts/files/outputs
4. Provide a restore/checkpoint service — tell the developer exactly what was contaminated and how to recover

This is different from simple forensics (which just replays what happened). It's about containment and recovery.

### Rigel's Feature Extraction Approach for RQ1
Rigel gave concrete guidance on how to build baseline policies:
1. Observe benign provenance graph
2. Extract features: what executables ran, what IPs were contacted, what actions were invoked, where actions came from
3. Summarize into patterns/profiles
4. Turn patterns into policy rules
5. At runtime, detect deviations from these patterns

He suggested looking at literature on **"provenance graphs and anomaly detection"** and specifically mentioned **Sekar's n-grams paper** as relevant.

### Key Quotes
- Venkat: "I don't want to get into a cycle where you bring things, I reject them, you go back..."
- Venkat: "This is a PhD. You need to read papers. There is no shortcut."
- Rigel on feature extraction: "What executables does it run? What IPs does it connect to? These are your features."

### Action Items from Meeting 12
- [ ] Rework RQ2 to be problem-driven (list CI/CD security challenges, not evaluate approach)
- [ ] Develop RQ3 contamination analysis idea
- [ ] Read "provenance graphs and anomaly detection" literature (Sekar's n-grams paper)
- [ ] Complete evaluation overview properly
- [ ] Read more papers — Venkat and Rigel both insisted

---

## Rafid's Mindset Shift (2026-04-22, self-reflection with Claude)

### The Problem Identified
Rafid has been struggling with research questions not because of intelligence, but because of a specific skill gap: **distinguishing between "what the system does" and "what is genuinely novel research."** He kept describing existing techniques applied to CI/CD as research questions. Venkat kept rejecting them for the same reason.

### Root Cause: Background Knowledge Gap
Rafid admitted he spent 30 minutes on the first 3 sentences of the Sleuth abstract — every sentence assumes knowledge he doesn't have yet. Without understanding the related work deeply, he can't identify what's novel because he doesn't know what's already been done.

### The AI Dependency Pattern
Observed pattern across sessions:
1. Rafid understands something technically
2. Asks Claude to draft research questions / bullets / messages
3. Goes into meeting unable to defend the reasoning because it's Claude's thinking, not his
4. Venkat sees through it, pushes back
5. Cycle repeats

### Resolution: Use Claude as Tutor, Not Ghostwriter
- For research thinking (RQs, novelty, framing) → Rafid must do the thinking first, Claude reviews
- For background learning → Claude explains concepts Rafid is stuck on (tutor mode)
- For infrastructure/code → Claude can just do it (nobody cares who wrote the YAML)
- Study Plan (6 modules at Study-Plan.md) is critical — needs to start ASAP to close the knowledge gap

### Key Insight
This is a normal first-year PhD struggle. The skill of identifying novel research takes time to develop. Rafid is not behind — he's learning.

---

## 8th Meeting Outcomes (2026-04-17, group meeting with Venkat, Rigel, Carlo)

### Overall Tone
Positive and constructive. Venkat was encouraging and pushing hard toward a submission deadline.

### Key Quote from Venkat
> "About 60% of what is needed to write a paper is done. Now, the important 40% comes... designing those scripts, doing some evaluation... it's brain work."

### Submission Target
Venkat is pushing toward **May 6th** (Usenix Security or NDSS). He said writing can be done in two weeks once the structure is clear. He proposed adding a **second weekly meeting on Mondays** to keep momentum.

### On Research Questions
Venkat pushed back on how the RQs were framed:
- They were too "leading" — they presuppose the answer
- Questions should NOT be binary yes/no — they should allow complex answers ("some cases better, some cases worse")
- Questions should be hierarchically organized: some are section-level, some subsection-level, not just a flat list
- Read other papers to see how research questions are phrased

### On Baseline Policy Generation (Section 3.1)
- Venkat called it *"the most substantial and novel"* part of the work
- *"Clearly, there exists no system today that allows for automatic policy generation"*
- Developer refinement is acceptable — doesn't need to be fully automatic
- The challenge: naive approaches will be too specific (e.g., DNS changes, variable name obfuscation break them)

### Paper Structure (confirmed)
- Section 3: System design — 3 subsections, each a novel contribution:
  - **3.1**: Baseline policy generation
  - **3.2**: Detection system
  - **3.3**: Forensics / tracing
- Section 4: Implementation details (eaudit, E* rules, etc.)
- For each of 3.1/3.2/3.3: create a figure + list of open research challenges

### On Harden-Runner Comparison
> "Harden-Runner just checks single events in isolation. We have stateful tracking of provenance across the whole workflow — therefore we can enforce a much richer set of policies."

This needs to be front and center in the evaluation.

### New Direction: AI-Generated Attacks
Rafid raised a blog post about GitHub AI agents. Venkat said: *"If we can detect attacks written by humans, we should also be able to detect attacks written by AI."* He suggested mentioning this in the discussion section as future work — not including it in the main paper.

### Deliverables for Next Meeting
- [ ] Refine research questions — restructure hierarchically, remove leading framing
- [ ] Evaluation overview — paragraph-level outline of the entire evaluation section
- [ ] Sketches for Sections 3.1, 3.2, 3.3 — figure + open research challenges for each
- [ ] Generate sample policies from benign workflow runs
- [ ] Add conference template (Usenix/NDSS) to Overleaf

### Note on Implementation
Venkat told Rafid separately (office visit) to get hands-on with the implementation — Carlo is doing too much and Rafid needs to learn independently. Study plan created at `Study-Plan.md`.

---

## Carlo Meeting 2 Outcomes (2026-04-17, Rafid + Carlo)

### Graph Comparison Approach for Section 3.1
Carlo and Rafid converged on using **graph comparison** as the core of baseline policy generation:
- Run benign workflow → capture provenance graph G1 (the baseline)
- Run with untrusted third-party actions → capture graph G2
- Measure graph distance between G1 and G2
- Deviations beyond a threshold = alarm
- This directly answers Venkat's baseline policy generation question

### Counterfactual Explanations for Section 3.3 (Forensics)
For the forensics section, Carlo proposed **counterfactual explanations**:
- Find the minimal modification to the attack graph that would make it look benign
- This tells the analyst exactly what changed — the smallest difference between the benign and attack graph
- Strong research angle: "what is the minimum set of edges/nodes that explain why this was flagged?"

### Key Decision: Single Path Assumption
Agreed to assume workflows have one execution path per run. Static analysis pre-computes all possible paths for conditional branches. This avoids exponential path explosion and simplifies policy generation significantly.

### Two-Step Policy Approach
- Generic policy: automatically generated from benign run (covers all detections)
- Developer whitelist: exceptions for things that trigger alarms but are known benign
- Developer annotates which files/env vars are secrets — system uses this for tagging

### Developer Input Required (important for Section 3.1)
The system cannot automatically know what is sensitive. Before running, the developer must provide:
1. **Which files/folders contain secrets** — so the system can tag them correctly
2. **Which env vars are sensitive** — since secrets are passed as execve args, not files
3. **Known-benign destinations whitelist** — to avoid false positives on legitimate outbound connections

Without this setup step, the system either flags everything (too many false positives) or misses things (tags nothing). This developer annotation step is part of the baseline policy generation flow in Section 3.1.

### Blockers
- Environment variable tracing when passed to child processes — not fully implemented
- Graph visualization tool — Carlo working on a notebook for this

---

## 7th Meeting Outcomes (2026-04-14, 1-on-1 with Venkat)

### What Happened
Rafid had the 1-on-1 that Venkat requested at the end of the 6th meeting. Rafid came in having course-corrected — sent Venkat a message the night before with the correct two-claim framing. Venkat accepted it and moved straight to research direction. Venkat set up Basecamp as a project management tool with 3 tasks.

### Venkat's Key Technical Point on Harden-Runner
Venkat articulated the core EAction vs Harden-Runner difference precisely:
> *"Harden-Runner just… there is no state context in Harden-Runner. They are looking at policies as essentially being applicable to single nodes or edges in our provenance graph... whereas we do have a stateful tracking of provenance across the whole workflow, and therefore it is possible to enforce a much richer set of policies."*

Concrete example he gave: "You can communicate to that attacker website, that's fine, but only so long as you have not read any sensitive files." — this policy requires state tracking across the workflow. Harden-Runner cannot do it. EAction can.

### The Three-Phase System Model (Venkat's vision)
Venkat described how EAction should work in three modes:

1. **Development time (baseline)**: Run the workflow with only trusted/internal components. Capture all behavior. This becomes the baseline security policy — what "normal" looks like.
2. **Runtime check**: When the workflow runs with third-party actions included, compare against the baseline. Deviations = alarm.
3. **Dry run / triaging**: For unknown third-party actions, optionally run them in isolation first to probe what they're capable of before deciding to trust them.

This three-phase model is the basis for **baseline policy generation** — one of the key research questions.

### Three Deliverables for Next Meeting (Thursday)
Venkat assigned these explicitly (also on Basecamp):

1. **Evaluation overview** — detection table + forensics comparison. Add to Overleaf. Two claims: (a) we detect attacks static tools miss, (b) we provide better causal chain than Harden-Runner.

2. **Research questions** — write as many as possible informed by prior work that showcase novelty. Venkat will pick the best ones. Paper needs 2-3 subsections (3.1, 3.2, 3.3) each representing a novel contribution.

3. **Approach for baseline policy generation** — sketch how EAction would learn a baseline from a benign workflow run, then use it to detect deviations when untrusted actions are introduced.

### Paper Structure (Venkat's guidance)
- Section 1: Introduction
- Section 2: Related work — firmly establishes no prior work solved this problem
- Section 3: System design — 2-3 subsections, each a novel contribution (NOT implementation details)
- Section 4: Implementation — eaudit, E* rules, technical details go here

"Section 3 is novel elements. Section 4 is implementation. What is in 3 is still novel."

### Important Note on Scope
Venkat: "You're building a research prototype, not a commercial product. Design test cases that cover common cases. As long as the system catches those in evaluation, that's good enough."

### Technical Issue Raised by Carlo
eBPF probe ignores `truncate` syscalls — so SolarWinds-style attack (overwrite source before compile) may not be caught. Venkat's suggestion: pull eaudit, make the fix in a branch, send to Sagar/Sekar.

### Next Meeting
Thursday (group meeting with Rigel). Monday group meeting was cancelled (Rigel busy with proposals).

---

## 6th Meeting Outcomes (2026-04-13, with Venkat, Rigel, Carlo + others)

### What Happened
Carlo demoed the 8 workflows (4 benign + 4 attack) and the detection system. Rafid presented evaluation metrics from literature. Venkat was not satisfied with Rafid's presentation.

### Venkat's Core Critique
Rafid came in with a table of metrics from 10 papers (SLEUTH, HOLMES, MORSE, UNICORN, ARGUS, etc.). Venkat's response:

> *"The only thing you need to worry about are the works that are applying that to securing GitHub Actions."*

> *"What is the state of art and how does this work improve the state of art?"*

> *"I'm not sure you understand what the problem is given to you... if you are spending time on things that are not of primary importance at this stage, that's a red flag."*

He wants a separate 1-on-1 meeting with Rafid to course correct. **Rafid must schedule this ASAP.**

### What Venkat Actually Wants
NOT a comprehensive metrics table from all provenance papers. YES: understand the specific contribution of EAction, identify the closest competing tools, and explain how EAction is better. Then metrics follow from that.

The framing he wants: **"If the author of SLEUTH reviewed our paper, what would they critique? How do we answer that?"**

### EAction's Research Contribution (Clarified)

**vs ARGUS and GHAST (static analysis tools):**
- They read the workflow YAML before execution — they never run anything
- They CANNOT detect any of our 4 attack types (exfil, malware, LotL, SolarWinds) because all 4 attacks happen at runtime inside the action script
- The YAML looks completely innocent — static tools see nothing wrong
- Our metric here: **detection coverage** — we catch attacks that static tools miss entirely

**vs Granite:**
- Permission reduction tool only, not attack detection
- Not a direct competitor

**vs Harden-Runner (StepSecurity):**
- This is our real competitor — it IS a runtime tool
- It monitors network egress, workflow dependencies, source code integrity
- It handles exfil, malware, and SolarWinds reasonably well via network monitoring
- It struggles with LotL (no network activity to monitor)
- BUT: it does not build a provenance graph — it cannot give you the full causal chain
- Example: Harden-Runner can say "suspicious outbound connection detected" but cannot say "the curl process got the secret because it was spawned by this third-party action which read it from the execve arguments of the runner process"
- **That full causal chain for forensics and root cause analysis is what provenance gives you**
- Rafid should verify Harden-Runner's documentation to confirm it has no provenance/forensics capability before claiming this

### The One-Line Contribution
**Static tools (ARGUS/GHAST) miss all runtime attacks. Runtime tools (Harden-Runner) catch some but cannot explain the causal chain. EAction provides runtime detection WITH provenance-based forensics — the first system to do both for CI/CD.**

### Metrics (now properly framed)
- **Detection coverage**: how many of the 4 attack types do we catch? (compare: ARGUS catches 0, Harden-Runner catches ~3)
- **False positive rate**: does the alarm fire on benign workflows? (our hardest problem — exfil)
- **Precision/Recall**: standard classification metrics for our own system
- **Provenance quality**: can we trace the attack back to its root cause? (qualitative, novel to our work)
- Provenance graph reduction metrics (SLEUTH-style) are **secondary** — not the headline

### Technical Updates from Meeting
- Carlo confirmed all 8 traces captured and working
- Tag initialization from workflow YAML is the right approach (Venkat confirmed)
- Third-party actions should be tagged untrusted based on namespace (not local ./github/actions but external org/repo@version) — this is a future improvement
- Workflow-scoped whitelist for network destinations is the right direction for reducing false positives
- Detection (not blocking) is the goal — confirmed by all

### Next Steps
- [ ] Rafid schedules 1-on-1 with Venkat ASAP to course correct
- [ ] Verify Harden-Runner documentation — does it do provenance/forensics?
- [ ] Reframe evaluation plan around the contribution (not metrics table)
- [ ] Run workflowDetect.ese against the 8 captured .out files — verify alarm fires on attacks, silent on benign

---

## 5th Meeting Outcomes (2026-04-11, with Rigel + Carlo + Prof. Venkat)

### Clarifications

**Tags go on nodes, not edges.**
Events (syscalls) are edges that show how information flows between nodes. Tags are properties of nodes (processes, files, IPs) and propagate from node to node as events occur. This was a source of confusion from tagnew.pdf — now resolved.

**Real-time vs after the fact:**
eaudit captures syscalls in real-time during the workflow run. E* rules fire on the provenance graph as events come in. The goal is **detection** (raise alarms), not **prevention** (block execution). Prof. Venkat: "prevention is not our purpose."

### Environment Variable Problem (novel contribution area)
Secrets in GitHub Actions are passed as `execve` arguments — they are not files/objects in the provenance graph, so they cannot be tagged directly.

- **Carlo's current workaround**: when the secret token string is detected in the execve args, tag the whole process with `conf(secret)`
- **Problem with this**: when backtracking forensically later, you hit the process and stop — there's no object to explain WHY it was tagged secret
- **Rigel's suggestion**: create a **synthetic fake object** to represent the env var as a graph node, tag it `conf(secret)` → gives a complete backtracking chain
- **Alternative**: create a new tag type like `conf(secret_env_var)` that encodes the env var origin
- This is **novel work** — Sleuth/Host doesn't handle env var tagging. This is an area for contribution.

### Benign vs Malicious Exfil — Pragmatic Resolution
No clean theoretical fix, but meeting converged on this approach:
1. Flag **everything** that looks like exfiltration (accept high false positives initially)
2. Add a **secondary filter**: check if the destination URL/IP was declared in the workflow file
3. Anything connecting to endpoints not in the workflow file = suspicious
4. This is workflow-scoped dynamic whitelisting — not a global whitelist, just per-workflow scope

This is what the **hardened runner** does at the network level. We do it at the provenance graph level.

### Per-Action Tagging (Rigel's idea — confirmed as next step)
Instead of binary untrusted/benign tags, encode the **origin action** in the tag itself using `def(i)/use(i)` from tagnew.pdf. Every node gets tagged with which specific action spawned it. This enables:
- Precise backtracking to the exact action that caused suspicious behavior
- Distinguishing between two third-party actions even if both are "untrusted"
- Rigel put notes about this ("Genesis" idea) in the **brainstorming Google Doc** → Rafid must check this

### Tag Initialization Approach
Parse the workflow YAML **before** execution starts → transitive closure to identify all third-party (untrusted) vs first-party (benign) actions → initialize tags statically before runtime → tags propagate dynamically during execution.

Carlo proposed: pre-process the workflow file to auto-generate E* rule initialization code (like C macros) so the tag setup happens at compile time, propagation at runtime.

### Carlo's Automation Script
Carlo has a bash script that automates the full eaudit capture loop:
1. Start eaudit
2. Start the GitHub Actions runner listener
3. Trigger workflow via GitHub API (needed because push-triggered workflows only fire once)
4. Wait for workflow to complete
5. Stop listener + stop eaudit
6. Save capture file

This works for their current demo workflows and will scale to running 100+ workflows.

### Next Steps (assigned in meeting)
- **Rafid**: Read existing papers (Sleuth, WATSON, etc.) → write **evaluation plan** — what metrics, how to show improvement over state of the art (due before Monday 1PM meeting)
- **Rafid**: Write **system architecture document** — two components: (1) workflow parser / policy creator, (2) monitoring/detection engine
- **Rafid**: Check Rigel's "Genesis" notes in the brainstorming Google Doc
- **Next meeting: Monday 1PM** (Rigel joining)

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

## Implementation Details: Detection Rules & Policies (discovered 2026-04-24)

### Where the detection rules live
- **`/Users/user/Desktop/nhost/Host/actions/workflowDetect.es`** — the ONLY custom `.es` detection module for GitHub Actions workflows
- It includes: `propTags.h` (tag propagation logic) and `initTagsWF.h` (initial tag assignments)
- **Updated by Carlo (confirmed 2026-04-25)** — now contains ALL detection modules, not just exfiltration

### What `workflowDetect.es` contains (UPDATED 2026-04-25)
ALL alarms are defined in this file. There are **5 detection modules** + **2 support modules**:

**Detection modules (universal policy):**
1. `detectExfiltration()` → `SensitiveExfiltration` alarm: process with SECRET tag writes to external network
2. `detectLocalActionNetworkWrite()` → `LocalActionNetworkWrite` alarm: local action (GITHUB_ACTION=__self) writes to external public network. Covers LotL and SolarWinds-style network exfil
3. `detectUnexpectedActionDownload()` → `UnexpectedActionDownload` alarm: local action writes untrusted file to /tmp/ after reading from network (unless allowlisted)
4. `detectUnexpectedActionExecution()` → `UnexpectedActionExecution` alarm: local action reads/executes an untrusted /tmp/ file
5. `detectUnexpectedWorkspaceWrite()` → `UnexpectedWorkspaceWrite` alarm: local action writes a .c source file in workspace (SolarWinds pattern). NOTE: does NOT fire on current attack trace because eaudit doesn't capture the O_TRUNC/printf redirect

**Support modules:**
6. `markLocalActionNetworkTaint()` — taints local-action subjects that read from external network as UNTRUSTED
7. `initAllowedLocalActionDownloads()` — ALLOWLIST module: resets tags for approved download sources (currently: nvm install script from githubusercontent.com). Must come after propTags.

**Initialization modules:**
- `initWorkflowSpecific()` — tags objects containing "dummytoken123" as SECRET
- `initRuntimeTokenObjects()` — same for runtime-created objects
- `initRunnerTokenSubjects()` — tags runner subjects with "dummytoken123" in cmdline as SECRET

### Key insight: the allowlist IS the specialized policy
The `initAllowedLocalActionDownloads()` module is the prototype of what a specialized policy looks like. It has a hardcoded allowlist entry for the nvm install script URL. In practice, generating a specialized policy means adding entries to this allowlist based on benign run observations. Currently this is manual (Carlo added the nvm entry by hand after seeing the benign-malware FP). The research question is how to automate this.

### What this means for "universal" vs "specialized" policy
- **Universal policy** = all 5 detection modules with NO allowlist entries. These fire on ANY workflow.
- **Specialized policy** = universal policy + allowlist entries derived from benign runs. The `initAllowedLocalActionDownloads` module is where suppressions go.
- The specialization is NOT just "suppress alarm X globally" — it's "suppress alarm X for THIS specific source/context" (e.g., allow downloads from nvm's URL but not from attacker.com)

### What does NOT exist yet
- No automated allowlist generation (currently Carlo manually adds entries after observing benign FPs)
- No policy representation format (allowlist is hardcoded in .es source, not a config file)
- SolarWinds detection rule exists but doesn't fire because eaudit misses the O_TRUNC syscall

### Tag initialization (`initTagsWF.h`)
- Default objects: BENIGN_AUTHENTIC + PUBLIC
- Local objects (`LOCAL:*`): BENIGN + PRIVATE
- IP objects (`IP:*`): UNTRUSTED + SENSITIVE
- Cert objects (`CERT:*`): BENIGN + PUBLIC
- `/bin/login`: INVULNERABLE + PUBLIC
- Default subjects: INVULNERABLE + BENIGN_AUTHENTIC + PUBLIC

### Tag propagation (`propTags.h`)
Conservative propagation: output inherits lowest integrity and highest confidentiality of all inputs. Key rules:
- `read`: subject inherits min integrity, min confidentiality from object read
- `load`/`execve`: subject inherits code integrity tag from loaded object
- `write`: object inherits min of subject and existing object tags
- `create`: new object gets subject's integrity tag + PUBLIC confidentiality
- `setuid`: if non-root, downgrade code integrity from INVULNERABLE to BENIGN_AUTHENTIC

---

## Demo Workflows (Carlo's repo: cfvescovo/eactions)

### Benign Workflows ✅ (all pushed)
- `benign-exfil-demo.yml` → uses `system-status-reporter` action (reads SECRET_TOKEN, curls to httpbin)
- `benign-malware-demo.yml` → uses `azure/setup-helm@v4` (downloads + installs Helm)
- `benign-lotl-demo.yml` → uses `cmake-builder` action (cmake + make on main.c)
- `benign-solarwinds-demo.yml` → uses `solarwinds-builder` action (cmake + make on deploy.c)

### Attack Workflows ✅ (all pushed to cfvescovo/eactions)
- Attack workflows call attack actions — workflows stay same, only action changes
- `attack-exfil-demo.yml` → calls `attack-exfil` action (does legit curl + also exfils to attacker.com)
- `attack-malware-demo.yml` → calls `attack-malware` action (does legit install + also downloads malware.sh from attacker.com)
- `attack-lotl-demo.yml` → calls `attack-lotl` action (cmake+make + writes evil.sh inline with echo, bash executes it, exfils $SECRET_TOKEN)
- `attack-solarwinds-demo.yml` → calls `attack-solarwinds` action (cmake, overwrites deploy.c with malicious printf, make deploy)

### Key Research Finding (from Carlo meeting 2026-04-08)
Benign and malicious exfiltration are **behaviorally identical** in the provenance graph — same pattern, only destination differs. Whitelisting is not the answer (endless list, Pastebin problem). This is an open research problem. Dynamic per-action tagging (Rigel's idea) may help distinguish them.

### C files in repo root
- `main.c` → hello world (used by cmake-builder / LotL demo)
- `deploy.c` → "Deploying..." (used by solarwinds-builder)
- `CMakeLists.txt` → builds both `hello` and `deploy` executables

---

## Next Actions

### IMMEDIATE (next meeting)
- [ ] **Rework RQ2 sub-questions** — Must be problem-driven not solution-driven. List CI/CD security challenges from the problem domain, not "is our approach enough?" (Meeting 12 feedback)
- [ ] **Develop RQ3: Contamination Analysis** — Venkat's new idea: detect → trace back → forward analysis → isolate contaminated artifacts → restore/checkpoint. Flesh this out.
- [ ] **Complete evaluation overview** — RQ1 needs Rigel's feature extraction approach (executables, IPs, action origins → patterns → rules). Move RQ1 table to RQ2 per Carlo.
- [ ] **Read papers** — "provenance graphs and anomaly detection" literature, Sekar's n-grams paper (Rigel's suggestion). Non-negotiable per Venkat.
- [ ] **Sketch and approach for baseline policy generation, triaging and runtime check** — assigned to Carlo on Basecamp (figures + open research challenges for Sections 3.1, 3.2, 3.3)
- [ ] **Start Study Plan** — Modules 1-3 (Linux processes, syscalls, networking) critical for reading papers independently

### Venkat's Feedback on RQs (2026-04-19)
Venkat asked: under each RQ, list what NEW research (not in any prior publication) will be performed.
He gave example for RQ1: (a) what is a baseline policy, (b) how to augment with project-specific policies, (c) how to represent for detection.

### Research Questions with Sub-Questions

**RQ1: How can we automatically derive a baseline policy from a benign workflow run?** ✅ Approved by Venkat
- How can we define a baseline policy from a CI/CD Provenance?
- How to incorporate project-specific policies (eg. unique behaviors, developer intent) in the baseline?
- How can these be summarized into a policy representation that can be used for detection later?
- How granular should the baseline policy be? (Too granular means high false positive, too coarse means missing attacks) ← new, not yet reviewed by Venkat

**RQ2: What attacks can be detected by detecting deviations from a learned baseline, that existing static and network-based tools miss?** ❌ Sub-questions need full rework

Round 1 bullets (rejected by Venkat, 9th meeting — answers already known from prior work):
- ~~How can we differentiate benign from malicious activity when they produce identical provenance patterns?~~ → Venkat: solved by tag propagation
- ~~How can we detect attacks that use only trusted tools?~~ → too vague
- ~~How do we detect file modifications done with malicious intent?~~ → too vague
- ~~What types of attacks can only be solved using stateful (runtime) tracking of events?~~ → property, not research question

Round 2 bullets (current state, discussing with Carlo):
1. ~~**How to correlate workflow-level steps (YAML) with system-level provenance for detection?**~~ → Rigel called this trivial in Meeting 10 (Caldera comparison). Marked for re-discussion with Carlo.
2. **How to detect behavioral change/deviation in trusted third-party actions after supply chain compromise?** — Not yet reviewed by anyone. The attacker IS a trusted action (codecov incident). Per-action behavioral profiles in the baseline, detecting when trusted action deviates.
3. **Are there attacks where tag propagation alone isn't enough?** — Experimentally confirmed: SolarWinds missed because file modification doesn't violate information flow. What new rule categories beyond tagging are needed?

**RQ3: What does a complete attack reconstruction look like in a CI/CD pipeline?** ⚠️ Venkat questioned whether substantive enough for a full section

Current bullet (marked for re-discussion with Carlo):
- ~~How can we map forensic provenance output back to specific instructions in workflow/action YAML files?~~ → Same problem as RQ2.1 (two-layer mapping). Rigel's "trivial" critique applies here too.

Open questions about RQ3:
- Is forensics substantive enough for its own section?
- Could fold into detection as a minor result
- Persistence across runs (Rigel's idea from Meeting 9 — interesting but hard to replicate)
- Need Carlo's input on whether he has enough novel forensics work

**Status (2026-04-23)**: Carlo discussion done (see Carlo Meeting 3 Outcomes). Meeting 12 happened — Venkat says RQ2 bullets are still solution-driven, need problem-driven rework. New RQ3 direction: contamination analysis. Rigel gave concrete RQ1 feature extraction approach. Need to rework RQ2 before next meeting.

### Harden-Runner vs EAction Forensics Comparison (from documentation + real run)
**Harden-Runner shows:** destination IP/domain, process name + PID, parent process (one level), HTTP method/path, which step. Does NOT show what data was sent. Requires manual cross-referencing across multiple tabs.
**EAction shows:** full command with actual secret value, destination IP, why it was flagged (SECRET tag from token= in args), which workflow and action. Full story in one alarm output.
See `detection-run-results.md` for all 8 scenario outputs.

### ALSO PENDING
- [ ] Generate sample policies from benign workflow runs
- [ ] Add Usenix/NDSS conference template to Overleaf
- [x] Run `workflowDetect.ese` against all 8 `.out` files on VM ✅ (2026-04-18)

### Detection Results (2026-04-18)
Command used: `./workflowDetect.ese runs/<name>.out -S 127.0.0.1:9999:9998 -R 127.0.0.1:127.0.0.1:9999`

| Scenario | Alarms | Result |
|---|---|---|
| attack-exfil | SensitiveExfiltration, LocalActionNetworkWrite | Detected ✅ |
| benign-exfil | SensitiveExfiltration, LocalActionNetworkWrite | False Positive ❌ |
| attack-malware | UnexpectedActionDownload, UnexpectedActionExecution, LocalActionNetworkWrite | Detected ✅ |
| benign-malware | LocalActionNetworkWrite | False Positive ❌ |
| attack-lotl | LocalActionNetworkWrite | Detected ✅ |
| benign-lotl | none | Clean ✅ |
| attack-solarwinds | none | Missed ❌ |
| benign-solarwinds | none | Clean ✅ |

**Key findings:**
- Malware and LotL detected correctly
- Exfil detected but benign also triggers — confirmed false positive problem (benign sends token to httpbin.org which looks identical to attack)
- SolarWinds missed — eaudit does not capture `truncate` syscalls, so source file overwrite before compilation is invisible
- Benign malware has one FP from git clone to GitHub IP during Helm install
- LotL attack: `stolen=` was empty in the alarm — secret token value not captured in the exfil payload

### PIPELINE
- [x] All 8 traces captured (attack + benign) ✅
- [x] Pipeline tutorial complete (Carlo filled in on 2026-04-14) ✅ — see `EAction-Pipeline-Tutorial-DRAFT.md`
- [ ] Fix `truncate` syscall missing in eBPF probe — branch eaudit, send fix to Sagar/Sekar
- [ ] Extend E* rules to cover malware, LotL, SolarWinds attacks (only exfil rule exists currently)

### OTHER ONGOING
- [ ] Check Rigel's "Genesis" notes in brainstorming Google Doc (Slack/Drive)
- [ ] Read about FQL/fqsh query language in Host codebase (Carlo knows this)
- [ ] Learn what dev/shm is (professor tested Rafid on this, didn't know)

---

## People & Contacts

| Person | Role | Contact |
|--------|------|---------|
| Prof. Venkat | Primary advisor UIC | Slack/email |
| Rigel Gjomemo | Research Scientist UIC | rgjome1@uic.edu |
| Carlo Federico Vescovo | Lab mate, VM admin | Slack (cvesc@uic.edu) |
| Sagar Mishra | Stony Brook, eConsumer dev | sagar.mishra.ntc@gmail.com |
| Prof. Sekar | Stony Brook, eaudit author | sekar@cs.stonybrook.edu |
