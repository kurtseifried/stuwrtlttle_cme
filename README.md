# CME — Common Mitigation Enumeration

A structured taxonomy of defensive security controls mapped to deterministic CVSS vector attenuation, served via an MCP (Model Context Protocol) server backed by a SQLite database.

---

## Table of Contents

- [Overview](#overview)
- [Why CME Exists](#why-cme-exists)
- [How It Relates to D3FEND](#how-it-relates-to-d3fend)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [MCP Server](#mcp-server)
  - [How It Runs](#how-it-runs)
  - [Query Tools (7)](#query-tools)
  - [Curation Tools (3)](#curation-tools)
  - [Resources (3)](#resources)
  - [Connecting to Claude Code](#connecting-to-claude-code)
  - [Connecting to Claude Desktop](#connecting-to-claude-desktop)
  - [MCP Inspector (Manual Testing)](#mcp-inspector)
- [Taxonomy Structure](#taxonomy-structure)
  - [Tactics](#tactics)
  - [Categories and Entry Counts](#categories-and-entry-counts)
  - [ID Numbering Convention](#id-numbering-convention)
  - [CVSS Attenuation Quick Reference](#cvss-attenuation-quick-reference)
- [Database](#database)
  - [Schema](#database-schema)
  - [Seeding](#seeding)
  - [Querying Directly](#querying-directly)
- [JSON Schema](#json-schema)
  - [Entry Structure](#entry-structure)
  - [Validation](#validation)
- [Multi-User Workflow](#multi-user-workflow)
  - [Proposing New Entries](#proposing-new-entries)
  - [Reviewing and Approving](#reviewing-and-approving)
  - [Git-Based Team Workflow](#git-based-team-workflow)
  - [Scaling to Shared On-Prem Deployment](#scaling-to-shared-on-prem-deployment)
- [Examples](#examples)
  - [AI Agent Risk Negotiation](#ai-agent-risk-negotiation)
  - [CWE-Based Mitigation Lookup](#cwe-based-mitigation-lookup)
  - [CVE Risk Simulation](#cve-risk-simulation)
- [Project Structure](#project-structure)
- [Sources and References](#sources-and-references)

---

## Overview

While **CVE** identifies specific vulnerabilities and **CWE** identifies classes of weaknesses, **CME** identifies the **defensive controls** that mitigate them. Each CME entry carries:

- A unique identifier (e.g., `CME-601`)
- The D3FEND-aligned tactic it belongs to (Harden, Isolate, Detect, Evict, Restore)
- The technology layer it operates at (Network, OS/Kernel, Application, Data, Identity)
- Specific CVSS base metrics it modifies (e.g., `S:C → S:U`, `AC:L → AC:H`)
- CWE weakness classes it mitigates (e.g., CWE-119, CWE-78)
- Machine-executable verification commands a scanner or agent can run to confirm the control is active
- Confidence level, platform applicability, and external references

## Why CME Exists

CVSS Environmental Scoring is rarely used because it requires manual, subjective judgment. A security analyst looks at a 9.8 Critical CVE and thinks *"I think our sandbox is pretty good, so I'll mark Confidentiality as Low."* This is a guess.

CME replaces guesswork with a lookup table. Instead of subjective assessment, the process becomes:

> "Asset `Server-01` has **CME-301 (SELinux Enforcing)** and **CME-601 (seccomp)** active. The taxonomy defines CME-301 as reducing `S:C → S:U` and `C:H → C:L`. The taxonomy defines CME-601 as reducing `S:C → S:U` and `I:H → I:L`. The Environmental Score is recalculated deterministically."

This enables:
- **Automated environmental scoring** by vulnerability scanners (Wiz, CrowdStrike, Qualys)
- **AI agent "Risk Negotiations"** where agents discover active controls and calculate effective risk
- **Dynamic risk tracking** — when a control is removed (EDR goes offline, firewall rule deleted), scores spike automatically
- **ROI justification** — "If we implement CME-402 (FIPS) across the fleet, our average Environmental Risk Score drops by 2.4 points"

## How It Relates to D3FEND

MITRE D3FEND is the structural inspiration for the CME taxonomy, but CME diverges in important ways:

| | D3FEND | CME |
|---|---|---|
| **Purpose** | Catalog defensive techniques generically | Map controls to *deterministic CVSS attenuation* |
| **Granularity** | Technique-level (e.g., "File Encryption") | Control-level with specific CVSS vector impact |
| **Output** | Knowledge graph of defenses | Lookup table for environmental scoring |
| **Relationship** | Mapped to ATT&CK offensively | Mapped to CWE root causes + CVSS metrics |
| **Control Layer** | Not a primary dimension | Core attribute (Network, OS/Kernel, App, Data, Identity) |
| **Verification** | Not included | Machine-executable commands per entry |

D3FEND's 5 tactic categories (Harden, Detect, Isolate, Deceive, Evict) are used as the organizational backbone, with Restore added and Deceive excluded (deception doesn't deterministically attenuate CVSS scores).

D3FEND mappings are preserved where they exist (e.g., CME-101 ASLR maps to D3FEND D3-SAOR Segment Address Offset Randomization), allowing cross-referencing between the two frameworks.

---

## Architecture

```
data/entries/              src/server.py              Clients
  CME-101.json        ┌─────────────────────┐
  CME-102.json        │   CME MCP Server    │     Claude Code
  CME-103.json        │   (FastMCP, stdio)  │ <── Claude Desktop
  ...                 │         |           │     AI Agents
  CME-1203.json       │    ┌────┴────┐      │     Scanners
       |              │    │ SQLite  │      │
       |              │    │ cme.db  │      │
  schema/             │    └─────────┘      │
  cme-entry.schema    └─────────────────────┘
       |                        ^
       v                        |
  src/validate.py         src/seed.py
  (schema checks)      (JSON → SQLite)
```

**Individual JSON files** (`data/entries/CME-*.json`) are the source of truth. The seed script loads them into a normalized SQLite database. The MCP server reads from SQLite and serves tools over stdio transport.

---

## Quick Start

```bash
# Install dependencies
uv sync

# Seed the database from entry files
uv run python -m src.seed

# Validate all entries against the schema
uv run python -m src.validate

# Run the MCP server (stdio — typically launched by a client, not manually)
uv run python -m src.server
```

---

## MCP Server

### How It Runs

The server uses **stdio transport** (the FastMCP default). It is **launched on-demand** by the MCP client (Claude Code, Claude Desktop, or any MCP-compatible client). You do not need to start or stop it manually. The client:

1. Spawns the server process
2. Communicates over stdin/stdout
3. Tears it down when the session ends

No ports, no daemon, no manual lifecycle management.

### Query Tools

| Tool | Description |
|------|-------------|
| `get_cme_entry` | Look up a specific CME entry by ID (e.g., `CME-601`). Returns the full entry with description, CVSS vector impacts, CWE relationships, verification commands, and references. |
| `search_cme` | Search entries by tactic (`Harden`, `Isolate`, `Detect`, `Evict`, `Restore`), category (`Kernel Hardening`, `Network Isolation`, etc.), control layer (`Network`, `OS/Kernel`, `Application`, `Data`, `Identity`), or free-text keyword across names and descriptions. |
| `get_mitigations_for_weakness` | Given a CWE ID (e.g., `CWE-119`), returns all CME controls that mitigate that weakness class. For CWE-119 (memory corruption), this returns 14 controls spanning ASLR, NX, SMEP, seccomp, gVisor, and more. |
| `calculate_attenuation` | Given a list of active CME-IDs on a system, aggregates all CVSS vector modifications. This is the core of CME: deterministic environmental scoring. |
| `simulate_cve_risk` | The "Risk Negotiation" tool. Feed in a CVE's base score, CVSS vector string, and active CME controls — get back the modified vector showing exactly how each metric shifts. |
| `list_cme_taxonomy` | Returns the full taxonomy hierarchy: all tactics with entry counts, all categories with their tactic, control layer, and counts. |
| `get_verification_commands` | Returns the shell commands a scanner or agent can run to verify whether a specific control is active on a target system. |

### Curation Tools

| Tool | Description |
|------|-------------|
| `propose_cme_entry` | Draft a new CME entry. Auto-assigns the next available CME-ID in the appropriate range, validates against the JSON schema, and writes to `data/proposals/`. Does NOT add to the live database until approved. |
| `list_proposals` | Lists all pending proposals awaiting review. |
| `approve_cme_proposal` | Moves a proposal from `data/proposals/` to `data/entries/` and inserts it into the live database. |

### Resources

| Resource URI | Description |
|---|---|
| `cme://taxonomy` | The full taxonomy structure |
| `cme://entry/{cme_id}` | A specific CME entry by ID |
| `cme://schema` | The CME JSON schema |

### Connecting to Claude Code

```bash
claude mcp add cme -- uv run --directory /Users/jwest/projects/cme python -m src.server
```

### Connecting to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cme": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/jwest/projects/cme", "python", "-m", "src.server"]
    }
  }
}
```

### MCP Inspector

To test tools interactively outside of a Claude client, use the MCP Inspector:

```bash
cd ~/projects/cme && uv run mcp dev src/server.py
```

This launches a web UI at `localhost:6274` where you can call all 10 tools and browse resources.

---

## Taxonomy Structure

### Tactics

The taxonomy uses 5 D3FEND-aligned tactics:

| Tactic | Purpose | CVSS Impact |
|--------|---------|-------------|
| **Harden** | Proactively reduce attack surface or increase exploitation difficulty | Directly modifies base metrics (AC, PR, S, C, I, A) |
| **Isolate** | Limit blast radius by restricting lateral movement and scope changes | Primarily modifies AV, S, PR |
| **Detect** | Identify malicious activity (detection alone is a compensating control) | Compensating: AC:L → AC:H when coupled with response |
| **Evict** | Remove or neutralize active threats; patch management | Temporal score reduction |
| **Restore** | Enable recovery and limit availability impact of successful attacks | Primarily modifies A |

### Categories and Entry Counts

```
Harden (43 entries)
├── Kernel Hardening (13): ASLR, NX, Stack Canaries, KASLR, SMEP, SMAP,
│   Module Restriction, kptr_restrict, Lockdown, KEXEC, Secure Boot, RELRO/PIE, CFI
├── Mandatory Access Control (4): SELinux Enforcing, Confined Users, Booleans, AppArmor
├── Cryptographic Controls (6): Crypto Policy, FIPS, TLS 1.3, Cert Pinning, DNSSEC, GPG
├── Filesystem Hardening (4): noexec /tmp, nosuid, dm-verity, IMA/EVM
├── Syscall & BPF Controls (4): seccomp, seccomp-bpf, BPF restriction, User Namespaces
├── Credential Hardening (6): MFA, pwquality, Account Lockout, SSH Key-Only, Rotation, Kerberos
├── Protocol Hardening (3): SSH Hardening, Disable Services, Kernel Network sysctl
└── Application Controls (3): WAF, CSP Headers, Rate Limiting

Isolate (17 entries)
├── Network Isolation (6): Zero Trust, firewalld, VLANs, IPsec/WireGuard, Localhost Bind, NetworkPolicy
├── Container Isolation (6): gVisor, Namespaces, Rootless, cgroups v2, Dropped Capabilities, Pod Security
├── Privilege Isolation (4): NoNewPrivileges, sudo Least Privilege, systemd Sandboxing, DynamicUser
└── Filesystem Hardening (1): Read-Only Root

Detect (4 entries)
├── Runtime Detection (3): EDR, auditd, Falco
└── Integrity Detection (1): AIDE

Evict (3 entries)
└── Patch Management (3): dnf-automatic, kpatch/livepatch, Container Image Rebuilds

Restore (3 entries)
└── Recovery Controls (3): Immutable Infrastructure, Backups, DR Failover
```

### ID Numbering Convention

| Range | Category |
|-------|----------|
| CME-100–199 | Kernel Hardening |
| CME-200–299 | Network Isolation |
| CME-300–399 | Mandatory Access Control (SELinux, AppArmor) |
| CME-400–499 | Cryptographic Controls |
| CME-500–599 | Filesystem Hardening |
| CME-600–699 | Syscall & BPF Controls |
| CME-700–799 | Container & Privilege Isolation |
| CME-800–899 | Credential & Identity Hardening |
| CME-900–999 | Network Protocol & Application Controls |
| CME-1000–1099 | Detection & Monitoring |
| CME-1100–1199 | Eviction & Patch Management |
| CME-1200–1299 | Restore & Recovery |

### CVSS Attenuation Quick Reference

How CME entries modify CVSS v4.0 Environmental metrics:

| Attenuation Type | CVSS Metric Modified | Example CME |
|-----------------|---------------------|-------------|
| Reduce Attack Vector | MAV: N → L or A | CME-201 (Zero Trust), CME-205 (Localhost Bind) |
| Increase Attack Complexity | MAC: L → H | CME-101 (ASLR), CME-401 (Crypto Policy) |
| Increase Privileges Required | MPR: N/L → H | CME-801 (MFA), CME-707 (NoNewPrivileges) |
| Reduce Scope | MS: C → U | CME-301 (SELinux), CME-701 (gVisor), CME-601 (seccomp) |
| Reduce Confidentiality Impact | MC: H → L/N | CME-301 (SELinux), CME-204 (IPsec) |
| Reduce Integrity Impact | MI: H → L/N | CME-504 (dm-verity), CME-601 (seccomp) |
| Reduce Availability Impact | MA: H → L | CME-704 (cgroups), CME-1201 (Immutable Infra) |

---

## Database

### Database Schema

The SQLite database uses a normalized schema with 5 tables:

```
cme_entries (main)
├── cme_id (PK), control_name, description, tactic, category,
│   control_layer, confidence, platforms_json, d3fend_technique_id/name
│
├── cvss_vector_impacts (1:many)
│   └── metric, from_value, to_value, rationale
│
├── cwe_relationships (1:many)
│   └── cwe_id
│
├── verification_commands (1:many)
│   └── method, command, expected, platform
│
└── references_ (1:many)
    └── source, url, section
```

Indexes on `tactic`, `control_layer`, `category`, `cwe_id` for fast lookups.

### Seeding

The database is generated from individual JSON entry files:

```bash
# Rebuild the database from data/entries/*.json
uv run python -m src.seed
```

Output: `data/cme.db` (SQLite, ~100KB for 71 entries)

### Querying Directly

The database can be queried directly with SQLite for debugging or integration:

```bash
# Count entries by tactic
sqlite3 data/cme.db "SELECT tactic, COUNT(*) FROM cme_entries GROUP BY tactic"

# Find all controls that mitigate CWE-119
sqlite3 data/cme.db "
  SELECT e.cme_id, e.control_name
  FROM cme_entries e
  JOIN cwe_relationships c ON e.cme_id = c.cme_id
  WHERE c.cwe_id = 'CWE-119'
"

# Show CVSS impacts for a specific control
sqlite3 data/cme.db "
  SELECT metric, from_value, to_value, rationale
  FROM cvss_vector_impacts
  WHERE cme_id = 'CME-601'
"
```

---

## JSON Schema

### Entry Structure

Each CME entry follows the schema at `schema/cme-entry.schema.json`. The core structure:

```json
{
  "cme_id": "CME-601",
  "control_name": "Kernel-Level Syscall Filtering (seccomp)",
  "description": "Restricts system calls a process can make...",
  "tactic": "Harden",
  "category": "Syscall & BPF Controls",
  "control_layer": "OS/Kernel",
  "cvss_vector_impacts": [
    {
      "metric": "S",
      "from": "C",
      "to": "U",
      "rationale": "Process cannot invoke blocked syscalls to escape to host kernel"
    }
  ],
  "cwe_relationships": ["CWE-119", "CWE-78"],
  "verification": {
    "method": "Check process seccomp status",
    "commands": [
      {
        "command": "grep Seccomp /proc/<pid>/status",
        "expected": "Seccomp:\t2",
        "platform": "linux"
      }
    ]
  },
  "d3fend_mapping": {
    "technique_id": "D3-SPP",
    "technique_name": "Stack Frame Canary Validation"
  },
  "confidence": "High",
  "platforms": ["RHEL 9", "RHEL 8", "Ubuntu 24.04", "Kubernetes"],
  "references": [
    {
      "source": "Red Hat Security Hardening Guide",
      "section": "Seccomp profiles"
    }
  ]
}
```

### Validation

Validate all entries against the schema:

```bash
uv run python -m src.validate
```

This checks:
- Every file in `data/entries/` passes the JSON schema
- Filenames match their `cme_id` field
- No duplicate CME-IDs exist

---

## Multi-User Workflow

### Proposing New Entries

Anyone with access to the MCP server can propose a new entry through natural conversation. The `propose_cme_entry` tool:

1. Auto-assigns the next available CME-ID in the appropriate number range
2. Validates the entry against the JSON schema
3. Writes the proposal to `data/proposals/CME-XXX.json`
4. Does **NOT** add it to the live database

Example via Claude:

> "Propose a CME entry for Landlock LSM filesystem sandboxing"

The tool returns the proposed entry with its assigned ID and file path.

### Reviewing and Approving

A reviewer can:

1. Call `list_proposals` to see all pending entries
2. Read and discuss the proposal
3. Call `approve_cme_proposal("CME-506")` to approve

Approval moves the file from `data/proposals/` to `data/entries/` and inserts it into the live database immediately.

### Git-Based Team Workflow

For teams, the `data/entries/` directory is the source of truth — one file per CME entry. The recommended flow:

```
User (via Claude)                 Git Repo                    Shared DB
────────────────                  ────────                    ─────────
"Add Landlock LSM"
        │
        ├─→ propose_cme_entry()
        │   writes data/proposals/CME-506.json
        │
        ├─→ git checkout -b add-cme-506
        │   git add data/proposals/CME-506.json
        │   (or move to data/entries/ directly)
        │   git push → open PR
        │
Reviewer reviews PR
        │
CI runs: uv run python -m src.validate
        │
Merge PR
        │
CI runs: uv run python -m src.seed ──────────→ Rebuilds cme.db
```

This ensures:
- Every new entry is reviewed before going live
- Schema validation catches errors in CI
- Full audit trail via git history
- Easy rollback by reverting a commit

### Scaling to Shared On-Prem Deployment

The current architecture (SQLite + stdio) is designed for single-user / small-team use. For a larger on-prem deployment with multiple concurrent users, the architecture would evolve:

```
Source of Truth          Shared Service            Clients
─────────────────       ──────────────────        ──────────
                        ┌──────────────────┐
  Git repo              │  CME MCP Server  │      Claude Code
  ├── data/entries/     │  (HTTP transport)│ <──  Claude Desktop
  │   ├── CME-101.json  │       |          │      AI Agents
  │   ├── CME-102.json  │  ┌────┴─────┐   │      Scanners
  │   └── ...           │  │ Postgres │   │
  ├── schema/           │  └──────────┘   │
  └── CI pipeline       └──────────────────┘
        │                       ^
        └───── CI seeds DB ─────┘
```

Key changes:
- **SQLite → PostgreSQL** for concurrent read/write access
- **stdio → HTTP transport** so one server process serves multiple clients
- **Git repo remains source of truth** — CI seeds the shared database on merge
- **Proposal workflow stays the same** — entries go through PR review before reaching the shared DB

---

## Examples

### AI Agent Risk Negotiation

This is the primary use case from the CME proposal — an AI security agent scanning a system discovers a CVE and automatically negotiates the effective risk:

```
Agent:  "I found CVE-2026-999 on Pod-Alpha. Calling simulate_cve_risk."

Server: {
  "original": {
    "score": 9.8,
    "vector": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  },
  "modifications_applied": 3,
  "modifications": [
    {
      "cme_id": "CME-201",
      "control_name": "Zero Trust Gateway / Identity-Aware Proxy",
      "metric": "AV", "from": "N", "to": "L",
      "rationale": "Network-accessible services are shielded behind identity verification"
    },
    {
      "cme_id": "CME-601",
      "control_name": "Kernel-Level Syscall Filtering (seccomp)",
      "metric": "S", "from": "C", "to": "U",
      "rationale": "Process cannot invoke blocked syscalls to escape to host kernel"
    },
    {
      "cme_id": "CME-601",
      "control_name": "Kernel-Level Syscall Filtering (seccomp)",
      "metric": "I", "from": "H", "to": "L",
      "rationale": "Blocked syscalls like execve/ptrace prevent shell breakout"
    }
  ],
  "modified_vector": "CVSS:4.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H"
}
```

The agent can then report: *"CVE-2026-999 has a base score of 9.8, but because CME-201 and CME-601 are active on Pod-Alpha, the effective risk is significantly lower. The modified vector can be fed into a CVSS calculator for the exact environmental score."*

### CWE-Based Mitigation Lookup

When a CVE's root cause is known (e.g., CWE-119 Memory Corruption), query for all applicable mitigations:

```
Tool:   get_mitigations_for_weakness("CWE-119")

Result: 14 controls
  CME-101: ASLR                    [AC:L → AC:H]
  CME-102: NX/XD Bit              [AC:L → AC:H]
  CME-104: KASLR                   [AC:L → AC:H]
  CME-105: SMEP                    [AC:L → AC:H, S:C → S:U]
  CME-106: SMAP                    [AC:L → AC:H]
  CME-108: kptr_restrict           [AC:L → AC:H]
  CME-112: RELRO and PIE          [AC:L → AC:H]
  CME-113: CFI / Shadow Call Stack [AC:L → AC:H]
  CME-601: seccomp                 [S:C → S:U, I:H → I:L]
  CME-602: seccomp-bpf Profile    [S:C → S:U, AC:L → AC:H]
  CME-603: Unprivileged BPF Disabled [PR:L → PR:H]
  CME-604: User Namespaces Disabled  [PR:L → PR:H, AC:L → AC:H]
  CME-701: gVisor Runtime         [S:C → S:U]
  CME-1102: Live Kernel Patching  [AC:L → AC:H]
```

### CVE Risk Simulation

For a real-world scenario like a Linux kernel eBPF privilege escalation:

```
Base Score: 8.8 (High)
Active Controls: CME-601 (seccomp), CME-101 (ASLR), CME-603 (BPF disabled)

Tool:   simulate_cve_risk(8.8, "CVSS:4.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                          ["CME-601", "CME-101", "CME-603"])

Result:
  CME-601: S:C → S:U  (seccomp prevents scope change)
  CME-101: AC:L → AC:H (ASLR increases complexity)
  CME-603: PR:L → PR:H (unprivileged BPF blocked)
  Modified vector: CVSS:4.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H
```

The effective risk drops dramatically — the attacker needs high privileges, high complexity, and cannot escape the process scope.

---

## Project Structure

```
~/projects/cme/
├── pyproject.toml                  # Python project config, dependencies
├── README.md                       # This file
├── schema/
│   └── cme-entry.schema.json       # JSON Schema for CME entries
├── data/
│   ├── entries/                    # Source of truth: one JSON file per CME entry
│   │   ├── CME-101.json
│   │   ├── CME-102.json
│   │   └── ... (71 files)
│   ├── proposals/                  # Pending proposals awaiting review
│   ├── cme.db                      # SQLite database (generated by seed script)
│   └── cme_seed_data.json          # Legacy single-file seed data
└── src/
    ├── __init__.py
    ├── db.py                       # Database layer: schema, queries, hydration
    ├── seed.py                     # Loads data/entries/*.json into SQLite
    ├── validate.py                 # Schema validation for all entry files
    └── server.py                   # MCP server: 10 tools, 3 resources
```

---

## Sources and References

- **CME Proposal**: Common Mitigation Enumeration Proposal (J. West, 2026)
- **MITRE D3FEND**: https://d3fend.mitre.org/ — Defensive technique taxonomy (structural inspiration)
- **Red Hat Security Hardening Guide**: RHEL 9 Security Hardening — primary source for Linux controls
- **CIS Benchmarks**: CIS Red Hat Enterprise Linux 9 Benchmark — verification commands and configuration standards
- **NIST SP 800-53**: Security and Privacy Controls for Information Systems
- **CVSS v4.0 Specification**: FIRST CVSS v4.0 — base metric definitions and environmental scoring
- **CVE JSON 5.1 Schema**: CVE record format for integration context
