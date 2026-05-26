# Lab: Configure ICMP Filters — `firewall-cmd --add-icmp-block`

- **Series:** linux-ops-mastery — RHCSA Firewall
- **Subjects covered:** ICMP types, **`echo-request`** vs **`echo-reply`**, **`firewall-cmd --add-icmp-block`**, **`--query-icmp-block`**, **`--list-icmp-blocks`**, **`--permanent`**, **`--reload`**, operational trade-offs (hiding vs breaking path MTU discovery)
- **Career arcs covered:** RHCSA (EX200 — reduce trivial network noise), RHCE (Ansible `icmp_block:`), SRE (mitigate reflection/flood noise — layered with real DDoS defenses), DevOps (lock down bastions), AI/MLOps (internal GPU headnodes that should not answer discovery pings)
- **Prerequisite:** Running `firewalld`; basic ICMP vocabulary; awareness that **blocking all ICMP** breaks some legitimate TCP flows
- **Time Estimate:** 30 to 45 minutes
- **Difficulty arc:** Task 1 inventory · 2–3 runtime block `echo-request` · 4 permanent + reload · 5 edge: query + optional `echo-reply` discussion · 6 capstone + remove blocks cleanup

---

## Objective

Use **`firewalld`** to block specific **ICMP message types** arriving at the host — starting with **`echo-request`** (the packet type `ping` sends). You will verify with **`--list-icmp-blocks`**, persist with **`--permanent`**, **`--reload`**, and remove blocks in cleanup so **`ping`** works again.

The capstone: *"Block ping floods at the firewall policy layer for the active zone — prove configuration before and after reload, then fully revert."*

> **Lab safety note:** Aggressive ICMP blocking on shared jump hosts can confuse monitoring that uses **`ping`** reachability probes — coordinate before applying outside your personal VM.

---

## Concept: ICMP Is Not One Protocol — It Is a Family of Control Messages

**ICMP** carries diagnostics: reachability (`echo-request` / `echo-reply`), errors (`destination-unreachable`), hints (`time-exceeded` for traceroute), and PMTUD (`fragmentation-needed`). `firewalld` exposes **per-type** blocks so you can stop **`ping`** noise without blindly deleting every ICMP packet.

```
   ping client
      │
      │ ICMP echo-request ────────────────┐
      ▼                                   ▼
   ┌──────────────────────────────────────────────┐
   │ RHEL host `firewalld` zone INPUT chain         │
   │   icmp-block: echo-request  ← THIS LAB         │
   └──────────────────────────────────────────────┘
      │
      └── (blocked) no echo-reply leaves host
```

> **Why this matters:** RHCSA wants **`--add-icmp-block=echo-request`** muscle memory — not "turn off ICMP" via vague folklore that also breaks TCP PMTUD.

---

## 📜 Why Selective ICMP Blocking Exists — The Story

Historically, administrators **`echo-request`**-blocked sensitive servers to reduce trivial network mapping — not because ICMP alone was a strong security boundary, but because it raised the cost of casual scanning.

Attackers abused ICMP in **reflection** and **flood** contexts; defenders responded with **rate limits** and **type-specific blocks**. Modern guidance still distinguishes **"block echo-request"** from **"block all ICMP"** — the latter often breaks path MTU discovery and makes TCP failures look random.

`firewalld` encodes this as **`icmp-block-inversion`** advanced knobs plus simple **`--add-icmp-block`** toggles for RHCSA-level tasks.

> **The point of the story:** You are learning **surgical ICMP policy**, not winning DDoS wars with a single flag — interviewers want you to say that out loud.

---

## 👪 The ICMP Block Family — Who Lives There

### Core commands

| Command | Role |
|---|---|
| `--get-icmptypes` | List types `firewalld` knows on this version |
| `--add-icmp-block=type` | Runtime block |
| `--remove-icmp-block=type` | Runtime remove |
| `--query-icmp-block=type` | Boolean test |
| `--list-icmp-blocks` | Human-readable runtime list |
| `--permanent` | Stage persistence |

### Common types in labs

| Type | Typical user-visible effect |
|---|---|
| `echo-request` | Stops answering `ping` probes |
| `echo-reply` | Uncommon to block locally — usually client-side |
| `timestamp-reply` / `timestamp-request` | Historical hardening targets |

### Danger zone (awareness)

| Too-broad pattern | Risk |
|---|---|
| Blocking **`fragmentation-needed`** | Path MTU black holes for TCP |

> **The point of the family tree:** Always **`--get-icmptypes`** on the target major release if a lab string fails — names are stable but your fingers might typo.

---

## 🔬 The Anatomy of `--add-icmp-block=echo-request` — In One Diagram

```
$ sudo firewall-cmd --add-icmp-block=echo-request
  │      │              │            │
  │      │              │            └─ ICMP type keyword understood by firewalld
  │      │              └─ action: merge block into runtime zone policy
  │      └─ CLI → firewalld → nftables icmp reject/drop rules (implementation detail)
  └─ root

Verify:
  sudo firewall-cmd --list-icmp-blocks
  ping -c 1 127.0.0.1    # localhost may still behave specially — prefer testing your NIC IP in real labs
```

> **Reading rule:** Localhost ICMP paths sometimes bypass the same INPUT chain semantics — for exams, follow the **`--list-icmp-blocks`** output as ground truth.

---

## 📚 ICMP Block Reference Table

| Task | Command | Notes |
|---|---|---|
| Discover valid names | `firewall-cmd --get-icmptypes` | Large list |
| Runtime block ping | `sudo firewall-cmd --add-icmp-block=echo-request` | Immediate |
| Runtime remove | `sudo firewall-cmd --remove-icmp-block=echo-request` | Immediate |
| Query | `sudo firewall-cmd --query-icmp-block=echo-request` | Exit status |
| Persist | `sudo firewall-cmd --permanent --add-icmp-block=echo-request` + `--reload` | Exam |
| List runtime | `sudo firewall-cmd --list-icmp-blocks` | Verify |
| List permanent | `sudo firewall-cmd --permanent --list-icmp-blocks` | Staged |

> **Rule one of ICMP labs:** Pair **`--add-icmp-block`** with **`--list-icmp-blocks`** every time — the list is your receipt.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Straightforward objective match: **block echo-request**, show lists, persist. |
| **RHCE candidate** | Ansible `firewalld` `icmp_block:` idempotency. |
| **SRE / Platform** | Understand limits — real floods need upstream scrubbing. |
| **DevOps** | Bastion hardening checklists often include disabling ping responses. |
| **AI / MLOps** | Internal cluster nodes sometimes should not advertise liveness via ICMP to untrusted VLANs. |

---

## 🔧 The 6 Tasks

> Build **list types → runtime block → observe ping → permanent + reload → query edge → cleanup remove**.

---

### Task 1 — Set up: list supported ICMP types and current icmp-blocks

**Purpose:** Confirm **`echo-request`** exists on this RHEL 9 image and note whether icmp-blocks are empty.

```bash
sudo firewall-cmd --state

sudo firewall-cmd --get-icmptypes | tr ' ' '\n' | grep -E '^echo-request$' || true

sudo firewall-cmd --list-icmp-blocks
sudo firewall-cmd --permanent --list-icmp-blocks
```

**Human-Readable Breakdown:** `tr` converts space-separated output to lines; `grep` proves the type exists. Both list commands establish baseline.

**Reading it left to right:** If `grep` finds nothing, your `firewalld` build uses unexpected naming — scroll raw `--get-icmptypes` output manually.

**The story:** Never memorize magic strings from blog posts — **`--get-icmptypes`** is the local authority.

**Expected output:**

```text
running
echo-request

```

**Switches**

| Token | Meaning |
|---|---|
| `--get-icmptypes` | Supported ICMP type keywords |
| `tr ' ' '\n'` | Token-per-line for easier grep |
| `--list-icmp-blocks` | Active blocks |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `not running` | Start `firewalld` |

---

### Task 2 — Core A: add runtime `echo-request` block and re-list

**Purpose:** Immediately stop **`echo-request`** handling for the zone — quick test before persistence.

```bash
sudo firewall-cmd --add-icmp-block=echo-request

sudo firewall-cmd --list-icmp-blocks
sudo firewall-cmd --query-icmp-block=echo-request && echo "echo-request blocked (runtime)"
```

**Human-Readable Breakdown:** Add, list, boolean query. Query exit code `0` means blocked.

**Reading it left to right:** Runtime-only — reboot or reload from clean permanent store removes unless mirrored.

**The story:** This is the **fast incident response** toggle when your honeypot is being ping-scanned by script kids.

**Expected output:**

```text
success
echo-request
echo-request blocked (runtime)
```

**Switches**

| Token | Meaning |
|---|---|
| `--add-icmp-block=type` | Block that ICMP type |
| `--query-icmp-block=type` | Boolean |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `INVALID_ICMP_TYPE` | Typo — re-check `--get-icmptypes` |
| Already blocked message | Safe to continue |

---

### Task 3 — Core B: observe behavior with `ping` (non-localhost target)

**Purpose:** From a **second shell** or remote VM, ping the lab IP — expect timeout when block works. Solo-VM learners can **`ping` the primary interface IP** from another terminal; loopback may not demonstrate INPUT filtering.

```bash
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
echo "Try: ping -c 3 $IP from another machine on the same L2 network"
```

**Human-Readable Breakdown:** Prints a plausible source IP for routing-based self-discovery — use **`hostname -I`** alternative if simpler in your environment.

**Reading it left to right:** ICMP INPUT filtering is easiest to see from **another host** on the subnet; all-local tests can be inconclusive.

**The story:** Document why **`ping 127.0.0.1`** is a weak test for INPUT firewalls — exam answers still rely on **`firewall-cmd --list-icmp-blocks`**, not ping folklore.

**Expected output:**

```text
Try: ping -c 3 192.0.2.50 from another machine on the same L2 network
```

**Switches**

| Token | Meaning |
|---|---|
| `ip route get` | Derive preferred source IP toward arbitrary destination |
| `ping -c 3` | Send three probes |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| No second host | Rely on `--query-icmp-block` + `--list-icmp-blocks` for proof |
| Still replies | Wrong zone — add `--zone=` matching uplink |

---

### Task 4 — Persistence: stage icmp-block in permanent configuration and reload

**Purpose:** Make **`echo-request`** block **survive reboot** — canonical exam sequence.

```bash
sudo firewall-cmd --permanent --add-icmp-block=echo-request

sudo firewall-cmd --permanent --list-icmp-blocks

sudo firewall-cmd --reload

sudo firewall-cmd --list-icmp-blocks
sudo firewall-cmd --query-icmp-block=echo-request && echo "still blocked after reload"
```

**Human-Readable Breakdown:** Permanent add, list staged, reload, confirm runtime still shows **`echo-request`**.

**Reading it left to right:** If runtime already had the block from Task 2, permanent add is idempotent-style success.

**The story:** Three proof artifacts: **permanent list**, **`reload` success**, **runtime list**.

**Expected output:**

```text
success
echo-request
success
echo-request
still blocked after reload
```

**Switches**

| Token | Meaning |
|---|---|
| `--permanent --add-icmp-block` | Persist block |
| `--reload` | Apply permanent → runtime |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Block missing after reload | Permanent add failed silently? Re-run with stderr visible |
| Duplicate lines in list | Usually still one logical block — cosmetic |

---

### Task 5 — Edge case: query inversion semantics awareness (read-only)

**Purpose:** Skim advanced **`icmp-block-inversion`** line in **`--list-all`** — you are not toggling it, just noting it exists for interviews.

```bash
sudo firewall-cmd --list-all | grep -i icmp
```

**Human-Readable Breakdown:** `icmp-block-inversion` changes how blocks combine — RHCSA rarely asks you to flip it; knowing the keyword exists separates book learners from practitioners.

**Reading it left to right:** `grep -i icmp` surfaces both **`icmp-block-inversion`** and **`icmp-blocks:`** summary lines depending on version formatting.

**The story:** If you ever see "ICMP allowed except these types" style configs, inversion is nearby — out of scope to edit blindly here.

**Expected output:**

```text
  icmp-block-inversion: no
  icmp-blocks:
    echo-request
```

**Switches**

| Token | Meaning |
|---|---|
| `grep -i icmp` | Case-insensitive filter |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| No `icmp-blocks:` section | Block not active — revisit Task 4 |

---

### Task 6 — Capstone + cleanup: remove `echo-request` block everywhere and reload

**Purpose:** Prove removal restores default ICMP handling for the lab VM — **always** end reachable for the next exercise.

```bash
sudo firewall-cmd --permanent --remove-icmp-block=echo-request
sudo firewall-cmd --remove-icmp-block=echo-request 2>/dev/null || true

sudo firewall-cmd --reload

sudo firewall-cmd --list-icmp-blocks
sudo firewall-cmd --query-icmp-block=echo-request; echo "query exit=$?"
```

**Human-Readable Breakdown:** Remove from permanent and runtime (ignore errors if already gone). Reload. List should be empty; query should fail with exit status **`1`**.

**The story:** Cleanup ensures **`ping`** monitoring returns green for whoever inherits the VM.

**Expected output:**

```text
success
success
success

query exit=1
```

**Cleanup**

```bash
sudo firewall-cmd --permanent --remove-icmp-block=echo-request 2>/dev/null || true
sudo firewall-cmd --remove-icmp-block=echo-request 2>/dev/null || true
sudo firewall-cmd --reload
sudo firewall-cmd --list-icmp-blocks
```

**Switches**

| Token | Meaning |
|---|---|
| `--remove-icmp-block` | Delete block |
| `echo "query exit=$?"` | Shows boolean result numerically |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Still blocked | Wrong zone — qualify `--zone=` consistently across add/remove |
| `ping` still fails | Another firewall layer (cloud SG) — outside this lab |

---

## 🔍 ICMP Blocking Decision Guide

```
Want to change ICMP behavior on RHEL 9?
  │
  ├── Only stop answering pings?
  │       └── `--add-icmp-block=echo-request`
  │
  ├── Need persistence?
  │       └── `--permanent ...` + `--reload` + `--list-icmp-blocks`
  │
  ├── Need path MTU intact?
  │       └── avoid blocking fragmentation-needed / packet-too-big classes
  │
  └── Need monitoring compatibility?
          └── document probe change before blocking in prod
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 `--get-icmptypes` sanity + baseline `--list-icmp-blocks`
- [ ] 02 Runtime `--add-icmp-block=echo-request` + query
- [ ] 03 Optional external `ping` test plan (second host)
- [ ] 04 `--permanent` block + `--reload` + re-verify
- [ ] 05 Read-only `--list-all \| grep -i icmp` awareness
- [ ] 06 Remove block (permanent + runtime) + reload + empty list

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| Blocked everything ICMP-adjacent via direct rules | Weird TCP MTU failures | Stay with selective `firewalld` types |
| Typo in type name | `INVALID_ICMP_TYPE` | `--get-icmptypes` |
| Forgot reload | Inconsistent views | `--reload` |
| Tested only loopback | False conclusions | External ping or trust `--query` |
| Left block on | Monitoring pages red | Task 6 cleanup |
| Wrong zone | No effect / wrong effect | `--zone=` alignment |
| Assumed this stops DDoS | Surprise under load | Rate-limit upstream |
| Confused `echo-request` vs `echo-reply` | Misdiagnosed direction | Read ping flow diagrams |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Memorize **`--add-icmp-block=echo-request` + `--permanent` + `--reload` + `--list-icmp-blocks`**.

**RHCE candidate**
- Map to Ansible `icmp_block:` string exactly.

**SRE / Platform interview**
- State limits: **this is not a DDoS scrubber** — it is hygiene and policy clarity.

**DevOps**
- Document monitoring probe protocol switch from ICMP to TCP health checks when disabling ping.

**AI / MLOps**
- GPU headnodes on flat networks: selective ICMP policy reduces trivial scanning footprint.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Rich rules | IP-specific policy layered with ICMP controls |
| Allow services | Reachability testing uses multiple protocols |
| Default zone | ICMP policy is per-zone |
| Masquerading / forwarding | ICMP related to PMTUD on forwarded paths |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
