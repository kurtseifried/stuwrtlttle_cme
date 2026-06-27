# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

CME (Common Mitigation Enumeration) is a taxonomy of defensive security controls, each mapped to **deterministic CVSS vector attenuation** (e.g. "control X shifts `S:C → S:U`"). Where CVE names vulnerabilities and CWE names weakness classes, CME names the controls that mitigate them. It is served as an **MCP server** (FastMCP) backed by SQLite (single-user) or PostgreSQL (multi-user), plus a generated static HTML site.

## The core architectural fact

**`data/entries/CME-*.json` is the single source of truth.** Everything else is derived from it:

- The **database** (SQLite `data/cme.db` or PostgreSQL) is rebuilt from the JSON files by `src/seed.py`. Editing the DB directly is futile — the next seed overwrites it.
- The **static site** in `docs/` is regenerated from the JSON files by `build_site.py`.

So the workflow for any taxonomy change is always: **edit/add JSON → validate → re-seed → rebuild site.**

## Common commands

```bash
uv sync                              # install deps
uv run python -m src.validate        # validate all entries against schema/cme-entry.schema.json
uv run python -m src.seed            # rebuild SQLite DB from data/entries/*.json
uv run python build_site.py          # regenerate docs/ static site (also: uv run build-site)
uv run python -m src.server          # run MCP server (stdio; normally launched by the MCP client)

# Multi-user (PostgreSQL + HTTP on :8000), via docker compose:
docker compose up -d                 # starts postgres, seeds it, runs server at http://localhost:8000/mcp
docker compose down -v               # full reset (drops pgdata volume)
```

There is **no test suite**. `src/validate.py` is the closest thing to a check — run it after any change to entry JSON or the schema. It verifies: filename matches `cme_id`, no duplicate IDs, and schema conformance.

Backend is selected by `CME_DB_BACKEND` (`sqlite` default / `postgres`); transport by `CME_TRANSPORT` (`stdio` default / `streamable-http`). See `src/config.py` for all env vars.

## Code layout

- `src/server.py` — all MCP tools and resources. Query tools (lookup by ID/tactic/CWE/CVSS vector, calculate attenuation, simulate CVE risk, coverage summary) and curation tools (`propose_cme_entry`, `approve_cme_proposal`, `list_proposals`).
- `src/db.py` (SQLite) and `src/db_postgres.py` (PostgreSQL) — parallel implementations of the same data-access interface. **Any schema or query change must be made in BOTH.** `server.py` imports one or the other based on `config.DB_BACKEND`.
- `src/seed.py`, `src/validate.py`, `src/config.py` — seeding, validation, configuration.
- `schema/cme-entry.schema.json` — JSON Schema (Draft 2020-12) for an entry; the contract validated by both `validate.py` and the MCP curation tools.
- `build_site.py` + `templates/` (Jinja2) → `docs/` (committed static site, served via GitHub Pages).
- `skills/cve-to-cme.md` — a Claude skill that maps CVE IDs to CME controls via this server's MCP tools.

## Conventions that aren't obvious

- **CME-ID number ranges are semantic.** `_CATEGORY_RANGES` in `src/server.py` assigns each category a numeric band (Kernel Hardening 101–, Network Isolation 201–, … Application Input Validation 1301–). The curation tools auto-assign the next free ID within the band, also scanning `data/proposals/` to avoid collisions. When adding a category, add it here.
- **The DB stores normalized child tables** (`cvss_vector_impacts`, `cwe_relationships`, `verification_commands`, `references_`) and `_hydrate()` in the db modules reassembles them back into the nested JSON shape that tools return. The SQL table is `references_` with a trailing underscore because `references` is a reserved word.
- **Tactics are fixed**: `Harden, Isolate, Detect, Evict, Restore` (D3FEND-aligned; Deceive is deliberately excluded, Restore added). **Control layers are fixed**: `Network, OS/Kernel, Application, Data, Identity`. Both are enforced by both the JSON schema and DB `CHECK` constraints.
- **Curation flow**: `propose_cme_entry` writes a validated draft to `data/proposals/`; `approve_cme_proposal` moves it to `data/entries/` and inserts it live. After approving, re-run `build_site.py` to refresh `docs/`.
- `insert_entry` is an upsert (`INSERT OR REPLACE` / Postgres equivalent) that clears and rewrites child rows, so re-seeding is idempotent.

## Git

`docs/` is committed (it's the published site), so a taxonomy change typically produces a large diff across `docs/entries/*.html` plus the edited `data/entries/*.json`. Regenerate `docs/` with `build_site.py` rather than hand-editing HTML. Per the user's global preference, default to a PR workflow rather than committing directly to `main`.
