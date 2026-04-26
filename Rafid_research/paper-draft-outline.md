# EAction: Runtime Security Monitoring for GitHub Actions Using Provenance-Based Detection

> This is my working draft to keep track of the bigger picture. Sections with [TODO] are not done yet. The goal is to have everything in one place so I don't lose context between sessions.

---

## Abstract

[TODO, write last, after everything else is done]

---

## 1. Introduction

### The Problem

GitHub Actions is the most popular CI/CD platform. Developers use third-party actions (reusable components) in their workflows to do things like build, test, and deploy code. The problem is: these third-party actions run with full access to secrets, source code, and the build environment. A malicious or compromised action can steal secrets, inject malware, or poison build artifacts, and the developer has no way of knowing.

Existing tools (ARGUS, GHAST, GWChecker, Sher, Granite) try to catch these problems using static analysis, they look at the workflow YAML file and try to spot vulnerabilities. But static tools can't see what actually happens at runtime. The malicious behavior is inside the action's source code, not in the YAML. For example, a workflow might say `uses: some-action@v1`, the YAML looks clean, but the action's code secretly reads a secret token and sends it to an attacker's server. Static analysis can't catch that.

The only runtime tool out there is Harden-Runner (by StepSecurity). It monitors network connections and file access during workflow execution. But it only looks at individual events in isolation, it does not track the flow of information across processes and files. So it can see "process X connected to IP Y" but it can't tell you "process X read secret Z, then sent it to IP Y because of action W." That causal chain is what provenance gives us.

### Our Approach

We built EAction, a system that uses kernel-level provenance tracing (via eaudit, an eBPF-based syscall tracer) to capture everything that happens during a GitHub Actions workflow run. From the trace, we build a provenance graph where nodes are processes and files, edges are syscalls (read, write, execve, connect), and tags track how trustworthy (integrity) and how sensitive (confidentiality) each entity is. Using this graph, we detect attacks by looking for suspicious information flows that violate security policies.

The key contribution is that we don't just use a one-size-fits-all policy. We have a universal policy (general detection rules that apply to any workflow) and a specialized policy (per-project allowlist entries learned from benign workflow runs). The specialized policy suppresses false positives that the universal policy produces on legitimate workflow behavior, while still catching real attacks.

### Research Questions

**RQ1: How can we automatically derive a baseline policy from a benign workflow run?**
- How can we define a baseline policy from a CI/CD provenance?
- How to incorporate project-specific policies (unique behaviors, developer intent)?
- How can these be summarized into a policy representation for detection?
- How granular should the baseline policy be?

**RQ2: What attacks can be detected by detecting deviations from a learned baseline, that existing static and network-based tools miss?**
[TODO, sub-questions need rework, must be problem-driven not solution-driven per Venkat Meeting 12 feedback]

**RQ3: [TODO, either contamination analysis (Venkat's idea) or dropped]**
Venkat proposed: after detecting suspicious action, go back in provenance graph, find everything it touched, forward analysis to isolate contaminated artifacts, provide restore/checkpoint service.

### Contributions

1. A system that captures kernel-level provenance during GitHub Actions workflow runs and builds a provenance graph with integrity and confidentiality tags
2. A two-tier policy approach (universal + specialized) where specialized policies are derived from benign workflow observations
3. Detection of 4 categories of supply chain attacks (secret exfiltration, malware download, living-off-the-land, build artifact poisoning) that existing static tools miss
4. [TODO, RQ3 contribution, contamination analysis or forensics]

---

## 2. Background

### 2.1 GitHub Actions

GitHub Actions is a CI/CD platform built into GitHub. Developers define workflows in YAML files (`.github/workflows/`). A workflow has jobs, and each job has steps. Steps can run shell commands or use actions, reusable components from the GitHub marketplace or other repos.

Third-party actions are referenced like `uses: owner/action-name@version`. When the workflow runs, GitHub's runner downloads and executes the action's code inside the workflow's environment. The action has access to:
- All secrets defined for the repository
- The source code (checked out in the workspace)
- The GITHUB_TOKEN (for API access)
- The full build environment (filesystem, network)

This is the attack surface. A compromised or malicious action can do anything a legitimate action can do, and the developer has no runtime visibility into what's actually happening.

### 2.2 Provenance Graphs

A provenance graph is a directed graph built from kernel-level syscall events. It captures the causal relationships between system entities:
- **Nodes**: subjects (processes) and objects (files, network connections)
- **Edges**: syscall events, read, write, execve, connect, clone, etc.

The direction of edges follows information flow. If a process reads a file, the edge goes from the file to the process (information flows from file to process). If a process writes to a file, the edge goes from the process to the file.

### 2.3 Information Flow Tags

Each entity in the provenance graph carries two types of tags:

**Integrity tags**, how trustworthy is the source:
- `invulnerable`: OS binaries, trusted system components
- `benign` (or `benign_authentic`): first-party code, verified sources
- `untrusted`: third-party actions, external downloads, attacker-controlled

**Confidentiality tags**, how sensitive is the data:
- `secret`: passwords, API tokens, signing keys
- `sensitive`: internal configuration, private data
- `private`: non-public but not sensitive
- `public`: freely shareable

**Tag propagation**: when a process reads an object, the process inherits the worst-case tags. Specifically, it gets the minimum integrity (most untrusted) and minimum confidentiality (most sensitive) of all its inputs. This is conservative, it never loses track of where untrusted or sensitive data flows.

### 2.4 The eaudit System

eaudit is an eBPF-based syscall tracer developed at Stony Brook University. It captures system calls at the kernel level without modifying applications. The pipeline:
1. `ecapd` (eBPF probes) captures syscalls during workflow execution
2. `eConsumer` translates raw syscalls into provenance events
3. `Host` builds the provenance graph, applies tags, propagates taint, and runs detection rules

The detection rules are written in the E* language, an event-pattern matching language where you define conditions on syscall events and their tags, and specify what alarm to raise when conditions are met.

---

## 3. System Design

### 3.1 Baseline Policy Generation (RQ1)

The goal is to automatically create a per-project security policy from a benign workflow run. This is needed because a universal policy (one that works for any workflow) inevitably produces false positives, legitimate workflow behaviors that look suspicious to general-purpose rules.

**Universal Policy:**
We start with 5 detection rules that apply to any workflow:
1. `SensitiveExfiltration`, process with SECRET tag writes to external network
2. `LocalActionNetworkWrite`, local action writes to external public network
3. `UnexpectedActionDownload`, local action downloads untrusted file to /tmp/
4. `UnexpectedActionExecution`, local action executes untrusted /tmp/ file
5. `UnexpectedWorkspaceWrite`, local action writes source file in workspace

These are the universal policy. They catch a broad range of suspicious behavior but produce false positives on workflows that legitimately do things like download tools, send status reports to external APIs, etc.

**Specialized Policy:**
To eliminate false positives, we run the workflow in a benign environment (training phase). Any alarm that fires during a benign run is, by definition, a false positive. But we don't just suppress the alarm type globally, we create an allowlist entry for the specific source or context that caused it.

For example, the benign malware workflow legitimately downloads nvm from `https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh`. This triggers `UnexpectedActionDownload`. The specialized policy adds an allowlist entry for that specific URL, so nvm downloads are allowed, but a download from `https://attacker.com/malware.sh` would still be caught.

Currently implemented as the `initAllowedLocalActionDownloads()` module in `workflowDetect.es`. Right now the allowlist entries are hardcoded. The research goal is to automate the generation of these entries from benign run observations.

[TODO, the automated generation process needs to be designed and implemented. Current idea: run benign trace → parse alarm output → extract source URLs/contexts → write to config file → load at runtime]

### 3.2 Attack Detection (RQ2)

[TODO, detection approach needs problem-driven framing per Venkat's feedback]

The detection system uses the specialized policy to monitor workflow runs. For each syscall event, tags are propagated through the provenance graph, and the 5 detection modules check whether security invariants are violated.

**What we detect and how:**

**Secret Exfiltration:** A process acquires the SECRET confidentiality tag (by reading a secret token) and then writes to an external network address. The alarm fires because secret data should not leave the workflow environment to unauthorized destinations.

**Malware Download & Execution:** A local action reads from an external network (getting tainted as UNTRUSTED), writes a file to /tmp/ (file inherits UNTRUSTED tag), and then the file is executed. The alarm fires because an untrusted file from the internet is being run.

**Living off the Land:** A local action uses pre-installed tools (curl, bash) to write data to an external network. Detected by `LocalActionNetworkWrite`, any local action writing to a public external IP is flagged.

**Build Artifact Poisoning (SolarWinds):** A local action overwrites a source file in the workspace before compilation. Detected by `UnexpectedWorkspaceWrite`. NOTE: this currently does not fire on our recorded traces because eaudit's eBPF probe does not capture the O_TRUNC syscall used by the bash redirect (printf > deploy.c). This is an implementation gap, not a detection logic gap.

### 3.3 Contamination Analysis (RQ3)

[TODO, Venkat proposed this in Meeting 12. The idea:]
After detecting a suspicious action:
1. Go back in the provenance graph, find everything the suspicious action touched
2. Forward analysis, trace all downstream effects (what files, artifacts, outputs were contaminated)
3. Isolate contaminated artifacts
4. Provide a restore/checkpoint service, tell the developer exactly what was contaminated and how to recover

This is different from simple forensics (which just replays what happened). It is about containment and recovery.

[TODO, needs design, implementation, and evaluation]

---

## 4. Implementation

### 4.1 Pipeline

The system runs on a self-hosted GitHub Actions runner on a Proxmox VM (managed by Carlo). The pipeline:

1. Developer pushes code → GitHub Actions workflow triggers
2. eaudit's eBPF probes capture all syscalls during the workflow run
3. eConsumer translates raw syscalls into provenance events
4. Host builds the provenance graph in memory
5. Tags are initialized based on the workflow context (secrets → SECRET, third-party actions → UNTRUSTED, OS binaries → INVULNERABLE)
6. Tag propagation runs on every read/write/execve event
7. Detection modules check for policy violations
8. Alarms are raised with full context (timestamp, process, object, command line)

### 4.2 Detection Rules (workflowDetect.es)

All detection rules are implemented in a single E* file: `workflowDetect.es`. It contains:

**Tag initialization:**
- `initTagsWF.h`, default tags for all entities (objects start BENIGN_AUTHENTIC+PUBLIC, subjects start INVULNERABLE+BENIGN_AUTHENTIC+PUBLIC, IPs start UNTRUSTED+SENSITIVE)
- `initWorkflowSpecific()`, tags objects containing the secret token as SECRET
- `initRuntimeTokenObjects()`, same for objects created at runtime
- `initRunnerTokenSubjects()`, tags runner subjects that handle tokens as SECRET

**Tag propagation:**
- `propTags.h`, conservative propagation rules. On read: subject gets min(integrity) and min(confidentiality) of itself and the object. On write: object gets min of subject and existing object tags. On execve: subject inherits code integrity from the executed object.

**Detection modules:**
- 5 detection modules (described in Section 3.2)
- `markLocalActionNetworkTaint()`, support module that taints subjects reading from external network
- `initAllowedLocalActionDownloads()`, allowlist module for specialized policy

### 4.3 Demo Workflows

We created 8 workflows (4 benign + 4 attack) in Carlo's repo (cfvescovo/eactions):

| Workflow | Benign Action | Attack Action |
|---|---|---|
| Exfiltration | status-reporter (reads token, curls to httpbin.org) | same + exfils to attacker.com |
| Malware | azure/setup-helm (downloads + installs Helm) | same + downloads malware.sh from attacker.com |
| Living off the Land | cmake-builder (cmake + make on main.c) | same + writes evil.sh with echo, executes it, exfils secret |
| SolarWinds | solarwinds-builder (cmake + make on deploy.c) | same + overwrites deploy.c before compilation |

All 8 traces have been captured and are stored in `/Users/user/Desktop/nhost/Host/actions/runs/`.

---

## 5. Evaluation

### 5.1 RQ1: Baseline Policy Generation

We evaluate the policy generation approach from 5 angles:

**Eval 1: Policy Necessity**
Show that the universal policy produces false positives on benign workflow runs, but the specialized policy eliminates them. This justifies why per-project policy generation is needed. Different workflows produce different specialized policies (different allowlist entries), proving one-size-fits-all does not work.

Inspired by SLEUTH Section 6.6, where they run on benign servers and show zero alarms after configuring policies for dpkg/apt.

| Workflow | Universal Policy Alarms on Benign | Specialized Policy Alarms on Benign |
|---|---|---|
| Exfil | [TODO, re-run with updated .es] | [TODO] |
| Malware | [TODO] | [TODO] |
| LotL | [TODO] | [TODO] |
| SolarWinds | [TODO] | [TODO] |

**Eval 2: Policy Stability Across Runs**
Generate a specialized policy from one benign run, then apply it to multiple other benign runs of the same workflow. Measure how many new false alarms appear on subsequent runs. If zero, one training run is sufficient. If some appear, we learn what varies between runs (DNS resolution, cache behavior, mirror selection) and what that means for policy generation.

Inspired by Holmes's noise reduction model trained on benign data, and SLEUTH's benign testing over 3-5 days.

[TODO, need to re-run benign workflows multiple times on the VM]

**Eval 3: Policy Size**
Report how many allowlist entries each workflow needs. A small number means the universal policy is well-calibrated. A large number means the workflow has complex benign behavior that looks suspicious.

| Workflow | Allowlist Entries Needed |
|---|---|
| Exfil | [TODO] |
| Malware | [TODO] |
| LotL | [TODO] |
| SolarWinds | [TODO] |

Inspired by SLEUTH Table 11 (graph reduction ratios), Granite (permission counts per job).

**Eval 4: Policy Generation Cost**
Time to run one benign workflow + time to analyze the trace and produce the policy. Standard systems metric.

[TODO, measure on next VM run]

Inspired by SLEUTH Table 9 (runtime and memory per campaign), Granite Table 5 (overhead per action).

**Eval 5: Granularity Analysis**
Analyze where the current suppression approach is too coarse or too fine. For example, suppressing `LocalActionNetworkWrite` for all destinations vs only for specific IPs. Too coarse = attacks slip through (false negatives during deployment). Too fine = benign variations trigger alarms (false positives during deployment). Discuss the tradeoff.

Inspired by SLEUTH Section 6.8 (split tags vs single tags, finer granularity reduces false positives).

Maps directly to RQ1 sub-question 4: "How granular should the baseline policy be?"

[TODO, qualitative analysis based on the allowlist module structure]

### 5.2 RQ2: Attack Detection

**Detection Results**

[TODO, re-run with updated workflowDetect.es and fill in]

| Scenario | Alarms | Result |
|---|---|---|
| attack-exfil | [TODO] | [TODO] |
| benign-exfil | [TODO] | [TODO] |
| attack-malware | [TODO] | [TODO] |
| benign-malware | [TODO] | [TODO] |
| attack-lotl | [TODO] | [TODO] |
| benign-lotl | [TODO] | [TODO] |
| attack-solarwinds | [TODO] | [TODO] |
| benign-solarwinds | [TODO] | [TODO] |

**Tool Comparison**

| Attack | GWChecker | GHAST | ARGUS | Sher | Granite | Harden-Runner | EAction |
|---|---|---|---|---|---|---|---|
| Secret Exfiltration | no | no | no | no | no | partial | yes |
| Malware Download & Execution | no | no | no | no | no | yes | yes |
| Build Artifact Poisoning | no | no | no | no | no | yes | no* |
| Living off the Land | no | no | no | no | no | no | yes |

*SolarWinds detection rule exists but doesn't fire due to eaudit missing O_TRUNC syscall.

Static tools (GWChecker, GHAST, ARGUS, Sher) cannot detect any of these because the attacks happen at runtime inside the action's code, the YAML workflow file looks clean. Granite enforces permissions at the step level but does not track information flow. Harden-Runner monitors network connections and file access but does not track causal chains across processes.

[TODO, need to verify Harden-Runner results with actual runs, not just documentation]

**Baseline Policy Generation (moved from RQ1 per Carlo's suggestion)**

| Workflow | Alarms on Benign (Universal) | Alarms on Benign (Specialized) | Alarms on Attack (Specialized) | Attack Caught? |
|---|---|---|---|---|
| Exfil | [TODO] | [TODO] | [TODO] | [TODO] |
| Malware | [TODO] | [TODO] | [TODO] | [TODO] |
| LotL | [TODO] | [TODO] | [TODO] | [TODO] |
| SolarWinds | [TODO] | [TODO] | [TODO] | [TODO] |

### 5.3 RQ3: Contamination Analysis

[TODO, not yet designed or implemented]

---

## 6. Related Work

### 6.1 Provenance-Based Detection Systems

**SLEUTH** (Hossain et al., USENIX Security 2017), real-time attack scenario reconstruction from audit data. Uses tag-based detection with integrity and confidentiality tags. Evaluated on DARPA red team engagements. Key difference from EAction: SLEUTH uses fixed general policies for enterprise systems. EAction needs to LEARN project-specific policies because what is "sensitive" or "expected" depends on the specific CI/CD workflow.

**Holmes** (Milajerdi et al., IEEE S&P 2019), real-time APT detection through correlation of suspicious information flows. Maps low-level alerts to APT kill-chain stages using a High-level Scenario Graph. Evaluated on DARPA TC data. Key difference: Holmes's TTP rules are manually defined for general enterprise attacks. EAction's detection rules are CI/CD-specific and include a per-project specialization mechanism.

### 6.2 GitHub Actions Security Tools

**ARGUS** (USENIX Security 2023), static taint analysis of GitHub Actions workflows. Tracks taint from sources (user-controlled inputs) to sinks (code execution, file writes). Found vulnerabilities in 2.7M workflows. Limitation: purely static, cannot detect runtime behavior of actions.

**GHAST** (Benedetti et al., CCS SCORED 2022), automated security analysis of GitHub Actions workflows. Identifies vulnerabilities and misconfigurations. Limitation: pattern-matching on YAML, cannot see inside action code.

**GWChecker** (Koishybayev et al., USENIX 2022), large-scale analysis of CI/CD security properties across platforms. Found 99.8% of workflows are overprivileged. Limitation: analyzes configurations, not runtime behavior.

**Sher** (Kumar & Madisetti, 2024), workflow scanning with ephemeral runners. Limitation: rule-based scanning with small-scale evaluation, no runtime detection.

**Granite** (Moazen et al., 2025), granular runtime enforcement of GitHub Actions permissions at the step level. Uses proxy-based interception of API calls. Limitation: enforces permissions (access control) but does not track information flow across processes.

**Harden-Runner** (StepSecurity), runtime monitoring of network connections and file access. Can block outbound connections to unauthorized IPs. Limitation: monitors individual events in isolation without tracking the causal chain. Cannot show that secret data flowed from env var → process → network. Does not detect LotL attacks where no new network connection is made.

### 6.3 Provenance Graphs and Anomaly Detection

[TODO, Sekar's n-grams paper and other literature Rigel mentioned]

---

## 7. Discussion

### Limitations

1. **Scale of evaluation**, we tested on 4 workflows with 4 attack types. Real-world CI/CD has thousands of workflow configurations. Future work: evaluate on real open-source projects.

2. **SolarWinds detection gap**, eaudit does not capture the O_TRUNC syscall, so the SolarWinds attack trace is incomplete. The detection rule is correct in principle but needs the eBPF probe to be extended.

3. **Manual allowlist generation**, currently, allowlist entries are hardcoded by hand. The automated generation from benign runs is proposed but not yet implemented.

4. **Single training run**, policy is generated from one benign run. Benign behavior may vary across runs (different IPs, different cache states). Need to evaluate stability.

5. **Offline analysis**, detection happens after workflow completion, not in real-time. This means an attack runs to completion before being detected. For CI/CD, this is acceptable (workflow runs are short, and the goal is detection not prevention), but it is a limitation compared to real-time systems like SLEUTH and Holmes.

### Future Work

[TODO]

---

## 8. Conclusion

[TODO]
