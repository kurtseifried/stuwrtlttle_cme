# Changelog

All notable changes to the CME (Common Mitigation Enumeration) project are documented here.

## 2026-06-28

### Category Registry (`e9de02c`)

Decoupled category membership from ID number ranges by introducing explicit `category_id` fields and a central category registry.

- **New file: `data/categories.json`** — defines all 16 categories with kebab-case slugs, descriptions, expected coverage scope for gap analysis, and advisory ID allocation ranges
- **Added `category_id`** to all 109 entry files (e.g., `"category_id": "kernel-hardening"`)
- **Updated schema** (`schema/cme-entry.schema.json`) — `category_id` is now a required field with pattern `^[a-z][a-z0-9-]*$`
- **Replaced hardcoded `_CATEGORY_RANGES`** in `src/server.py` with data-driven `_load_categories()` from `categories.json`
- **MCP tool updates:**
  - `search_cme()` accepts `category_id` parameter alongside `category`
  - `propose_cme_entry()` accepts `category_id` and derives the category name from the registry
  - `list_cme_taxonomy()` returns the full category registry including descriptions and expected coverage scope
- **Validation** (`src/validate.py`) now cross-references each entry's `category_id` against the registry and warns on ID-range misalignment
- **Database layers** (`src/db.py`, `src/db_postgres.py`) — added indexed `category_id TEXT` column to `cme_entries` table

### Windows Platform Support (`6f37095`)

Added Windows verification commands and platform applicability to 37 entries.

- **Tier 1 (11 entries):** Added PowerShell verification commands with `platform: "windows"` for controls with direct Windows equivalents:
  - CME-101 (ASLR): `Get-ProcessMitigation` checks for ForceRelocateImages and BottomUp
  - CME-102 (NX/DEP): `DataExecutionPrevention_SupportPolicy` check
  - CME-111 (Secure Boot): `Confirm-SecureBootUEFI`
  - CME-113 (CFI/CFG): `Get-ProcessMitigation` CFG.Enable check
  - CME-403 (TLS 1.3): `SecurityProtocol` TLS13 band check
  - CME-407 (Encryption): `Get-BitLockerVolume` ProtectionStatus and EncryptionMethod
  - CME-802 (Password Quality): `net accounts` minimum password length
  - CME-803 (Account Lockout): `net accounts` lockout threshold and duration
  - CME-805 (Credential Rotation): `net accounts` maximum password age
  - CME-902 (Disable Services): `Get-NetTCPConnection` listening port audit
  - CME-1001 (EDR): Windows Defender ATP `Sense` service and `RealTimeProtectionEnabled` checks
- **Tier 1 entries also received** `cve_affected` blocks with Microsoft Windows CPEs (Win10, Win11, Server 2019, Server 2022)
- **Tier 2 (26 entries):** Added "Windows Server 2019" and "Windows Server 2022" to the `platforms` array for application-layer controls (CME-904 through CME-917, CME-1301 through CME-1313) whose `platform: "any"` verification commands already work on Windows
- **Renamed CME-407** to "Data-at-Rest Encryption (LUKS/dm-crypt / BitLocker)" to reflect cross-platform scope

### Multi-Platform Product Applicability (`792beb1`)

Adopted the CVE Record Format 5.2.0 `affected[]` container shape for structured product identity.

- **New fields:** `cve_affected` (array of product blocks) and `cve_schema_version` (pinned to "5.2.0")
- **CME status semantics:** `applicable` / `not-applicable` / `unknown` (analogous to CVE's affected/unaffected/unknown)
- **Product identity support:** CPE 2.2/2.3, Package URL (PURL), vendor+product, platform overlap
- **New MCP tool:** `get_mitigations_for_product()` (13th tool) — structural joins by CPE prefix, PURL, vendor+product, or platform
- **Schema additions:** `$defs/cme_product`, `$defs/cme_status`, `$defs/cme_version` with `dependentRequired` constraint (cve_affected requires cve_schema_version)
- **Proof-of-concept entries:** CME-101 (cross-platform ASLR), CME-301 (Linux SELinux), CME-206 (Kubernetes NetworkPolicy with GKE/EKS/AKS)
- **Static site:** Applicability section added to entry pages showing vendor, product, CPEs, platforms, and status

### PostgreSQL Schema Migration Fix (`f6663db`)

Fixed a bug where `CREATE TABLE IF NOT EXISTS` prevented new columns from being added to existing PostgreSQL databases on re-seed.

- `init_db()` now drops all tables with `CASCADE` before recreating them, matching the SQLite backend's wipe-and-rebuild behavior
- Ensures `cve_schema_version` and `cve_affected_json` columns (and later `category_id`) are created when re-seeding an existing database

### External Contribution (`d8a8f24`)

Merged PR #1 from @kurtseifried — README refresh with updated entry counts, detailed ID numbering table referencing `_CATEGORY_RANGES`, CI schema-validation workflow (`.github/workflows/validate.yml`), and proposals directory cleanup.
