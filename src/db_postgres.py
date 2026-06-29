"""CME Database layer — PostgreSQL backend for multi-user deployments."""

import json

import psycopg
from psycopg.rows import dict_row

from . import config

_conn = None


def get_connection() -> psycopg.Connection:
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg.connect(
            host=config.PG_HOST,
            port=config.PG_PORT,
            user=config.PG_USER,
            password=config.PG_PASSWORD,
            dbname=config.PG_DATABASE,
            row_factory=dict_row,
            autocommit=False,
        )
    return _conn


def init_db(conn: psycopg.Connection) -> None:
    for table in ["references_", "verification_commands", "cwe_relationships",
                  "cvss_vector_impacts", "cme_entries"]:
        conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")

    conn.execute("""
        CREATE TABLE cme_entries (
            cme_id          TEXT PRIMARY KEY,
            control_name    TEXT NOT NULL,
            description     TEXT NOT NULL,
            tactic          TEXT NOT NULL CHECK(tactic IN ('Harden','Isolate','Detect','Evict','Restore')),
            category        TEXT NOT NULL,
            category_id     TEXT NOT NULL,
            control_layer   TEXT NOT NULL CHECK(control_layer IN ('Network','OS/Kernel','Application','Data','Identity')),
            confidence      TEXT CHECK(confidence IN ('High','Medium','Low')),
            platforms_json  TEXT,
            d3fend_technique_id   TEXT,
            d3fend_technique_name TEXT,
            cve_schema_version    TEXT,
            cve_affected_json     TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE cvss_vector_impacts (
            id          SERIAL PRIMARY KEY,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            metric      TEXT NOT NULL CHECK(metric IN ('AV','AC','PR','UI','S','C','I','A')),
            from_value  TEXT NOT NULL,
            to_value    TEXT NOT NULL,
            rationale   TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE cwe_relationships (
            id      SERIAL PRIMARY KEY,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            cwe_id  TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE verification_commands (
            id          SERIAL PRIMARY KEY,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            method      TEXT,
            command     TEXT NOT NULL,
            expected    TEXT NOT NULL,
            platform    TEXT DEFAULT 'linux'
        )
    """)
    conn.execute("""
        CREATE TABLE references_ (
            id      SERIAL PRIMARY KEY,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            source  TEXT NOT NULL,
            url     TEXT,
            section TEXT
        )
    """)

    # Create indexes (IF NOT EXISTS works for indexes in PostgreSQL)
    for stmt in [
        "CREATE INDEX IF NOT EXISTS idx_entries_tactic ON cme_entries(tactic)",
        "CREATE INDEX IF NOT EXISTS idx_entries_layer ON cme_entries(control_layer)",
        "CREATE INDEX IF NOT EXISTS idx_entries_category ON cme_entries(category)",
        "CREATE INDEX IF NOT EXISTS idx_entries_category_id ON cme_entries(category_id)",
        "CREATE INDEX IF NOT EXISTS idx_cvss_cme ON cvss_vector_impacts(cme_id)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_cme ON cwe_relationships(cme_id)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_relationships(cwe_id)",
    ]:
        conn.execute(stmt)

    conn.commit()


def insert_entry(conn: psycopg.Connection, entry: dict) -> None:
    conn.execute(
        """INSERT INTO cme_entries
           (cme_id, control_name, description, tactic, category, category_id, control_layer,
            confidence, platforms_json, d3fend_technique_id, d3fend_technique_name,
            cve_schema_version, cve_affected_json)
           VALUES (%(cme_id)s, %(control_name)s, %(description)s, %(tactic)s, %(category)s,
                   %(category_id)s, %(control_layer)s, %(confidence)s, %(platforms_json)s,
                   %(d3fend_technique_id)s, %(d3fend_technique_name)s,
                   %(cve_schema_version)s, %(cve_affected_json)s)
           ON CONFLICT (cme_id) DO UPDATE SET
               control_name = EXCLUDED.control_name,
               description = EXCLUDED.description,
               tactic = EXCLUDED.tactic,
               category = EXCLUDED.category,
               category_id = EXCLUDED.category_id,
               control_layer = EXCLUDED.control_layer,
               confidence = EXCLUDED.confidence,
               platforms_json = EXCLUDED.platforms_json,
               d3fend_technique_id = EXCLUDED.d3fend_technique_id,
               d3fend_technique_name = EXCLUDED.d3fend_technique_name,
               cve_schema_version = EXCLUDED.cve_schema_version,
               cve_affected_json = EXCLUDED.cve_affected_json""",
        {
            "cme_id": entry["cme_id"],
            "control_name": entry["control_name"],
            "description": entry["description"],
            "tactic": entry["tactic"],
            "category": entry["category"],
            "category_id": entry["category_id"],
            "control_layer": entry["control_layer"],
            "confidence": entry.get("confidence"),
            "platforms_json": json.dumps(entry.get("platforms", [])),
            "d3fend_technique_id": entry.get("d3fend_mapping", {}).get("technique_id"),
            "d3fend_technique_name": entry.get("d3fend_mapping", {}).get("technique_name"),
            "cve_schema_version": entry.get("cve_schema_version"),
            "cve_affected_json": json.dumps(entry["cve_affected"]) if entry.get("cve_affected") else None,
        },
    )

    # Clear child rows for upsert
    for table in ("cvss_vector_impacts", "cwe_relationships", "verification_commands", "references_"):
        conn.execute(f"DELETE FROM {table} WHERE cme_id = %(cme_id)s", {"cme_id": entry["cme_id"]})

    for impact in entry.get("cvss_vector_impacts", []):
        conn.execute(
            """INSERT INTO cvss_vector_impacts (cme_id, metric, from_value, to_value, rationale)
               VALUES (%(cme_id)s, %(metric)s, %(from)s, %(to)s, %(rationale)s)""",
            {"cme_id": entry["cme_id"], "metric": impact["metric"],
             "from": impact["from"], "to": impact["to"], "rationale": impact.get("rationale")},
        )

    for cwe in entry.get("cwe_relationships", []):
        conn.execute(
            "INSERT INTO cwe_relationships (cme_id, cwe_id) VALUES (%(cme_id)s, %(cwe_id)s)",
            {"cme_id": entry["cme_id"], "cwe_id": cwe},
        )

    verification = entry.get("verification", {})
    method = verification.get("method")
    for cmd in verification.get("commands", []):
        conn.execute(
            """INSERT INTO verification_commands (cme_id, method, command, expected, platform)
               VALUES (%(cme_id)s, %(method)s, %(command)s, %(expected)s, %(platform)s)""",
            {"cme_id": entry["cme_id"], "method": method, "command": cmd["command"],
             "expected": cmd["expected"], "platform": cmd.get("platform", "linux")},
        )

    for ref in entry.get("references", []):
        conn.execute(
            "INSERT INTO references_ (cme_id, source, url, section) VALUES (%(cme_id)s, %(source)s, %(url)s, %(section)s)",
            {"cme_id": entry["cme_id"], "source": ref["source"],
             "url": ref.get("url"), "section": ref.get("section")},
        )


# --- Query helpers ---

def get_entry(conn: psycopg.Connection, cme_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cme_entries WHERE cme_id = %(cme_id)s", {"cme_id": cme_id}).fetchone()
    if not row:
        return None
    return _hydrate(conn, dict(row))


def search_entries(
    conn: psycopg.Connection,
    *,
    tactic: str | None = None,
    category: str | None = None,
    control_layer: str | None = None,
    keyword: str | None = None,
) -> list[dict]:
    clauses = []
    params: dict = {}
    if tactic:
        clauses.append("tactic = %(tactic)s")
        params["tactic"] = tactic
    if category:
        clauses.append("category = %(category)s")
        params["category"] = category
    if control_layer:
        clauses.append("control_layer = %(control_layer)s")
        params["control_layer"] = control_layer
    if keyword:
        clauses.append("(control_name ILIKE %(kw)s OR description ILIKE %(kw)s)")
        params["kw"] = f"%{keyword}%"

    where = " AND ".join(clauses) if clauses else "1=1"
    rows = conn.execute(
        f"SELECT * FROM cme_entries WHERE {where} ORDER BY cme_id", params
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_mitigations_for_cwe(conn: psycopg.Connection, cwe_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT e.* FROM cme_entries e
           JOIN cwe_relationships c ON e.cme_id = c.cme_id
           WHERE c.cwe_id = %(cwe_id)s
           ORDER BY e.cme_id""",
        {"cwe_id": cwe_id},
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_attenuation_for_cve(conn: psycopg.Connection, active_cme_ids: list[str]) -> list[dict]:
    if not active_cme_ids:
        return []
    # Use ANY for array-based IN clause
    rows = conn.execute(
        """SELECT e.cme_id, e.control_name, v.metric, v.from_value, v.to_value, v.rationale
           FROM cme_entries e
           JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
           WHERE e.cme_id = ANY(%(ids)s)
           ORDER BY e.cme_id, v.metric""",
        {"ids": active_cme_ids},
    ).fetchall()
    return [dict(r) for r in rows]


def list_tactics(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT tactic, COUNT(*) as count FROM cme_entries GROUP BY tactic ORDER BY tactic"
    ).fetchall()
    return [dict(r) for r in rows]


def list_categories(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT tactic, category, control_layer, COUNT(*) as count
           FROM cme_entries GROUP BY tactic, category, control_layer
           ORDER BY tactic, category"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_mitigations_for_vector(
    conn: psycopg.Connection,
    metric_pairs: list[tuple[str, str]],
) -> list[dict]:
    """Find CME entries whose CVSS impacts match any of the given (metric, value) pairs."""
    if not metric_pairs:
        return []
    clauses = []
    params: dict[str, str] = {}
    for i, (metric, value) in enumerate(metric_pairs):
        clauses.append(f"(v.metric = %(m{i})s AND v.from_value = %(v{i})s)")
        params[f"m{i}"] = metric
        params[f"v{i}"] = value
    where = " OR ".join(clauses)
    rows = conn.execute(
        f"""SELECT DISTINCT e.*, v.metric AS matched_metric,
                   v.from_value, v.to_value, v.rationale AS impact_rationale
            FROM cme_entries e
            JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
            WHERE {where}
            ORDER BY v.metric, e.cme_id""",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def get_coverage_summary(conn: psycopg.Connection) -> dict:
    """Return a summary of CWE and CVSS metric coverage across all CME entries."""
    cwe_rows = conn.execute(
        """SELECT cwe_id, COUNT(DISTINCT cme_id) as entry_count
           FROM cwe_relationships GROUP BY cwe_id ORDER BY entry_count DESC"""
    ).fetchall()

    cvss_rows = conn.execute(
        """SELECT metric, from_value, to_value, COUNT(DISTINCT cme_id) as entry_count
           FROM cvss_vector_impacts GROUP BY metric, from_value, to_value
           ORDER BY metric, from_value"""
    ).fetchall()

    total = conn.execute("SELECT COUNT(*) as count FROM cme_entries").fetchone()

    return {
        "total_entries": total["count"],
        "cwe_coverage": [dict(r) for r in cwe_rows],
        "cvss_coverage": [dict(r) for r in cvss_rows],
    }


def get_entries_with_cve_affected(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM cme_entries
           WHERE cve_affected_json IS NOT NULL
           ORDER BY cme_id"""
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def _hydrate(conn: psycopg.Connection, entry: dict) -> dict:
    cme_id = entry["cme_id"]
    entry["platforms"] = json.loads(entry.pop("platforms_json") or "[]")

    cve_affected_raw = entry.pop("cve_affected_json", None)
    if cve_affected_raw:
        entry["cve_affected"] = json.loads(cve_affected_raw)
    schema_version = entry.pop("cve_schema_version", None)
    if schema_version:
        entry["cve_schema_version"] = schema_version

    if entry.get("d3fend_technique_id"):
        entry["d3fend_mapping"] = {
            "technique_id": entry.pop("d3fend_technique_id"),
            "technique_name": entry.pop("d3fend_technique_name"),
        }
    else:
        entry.pop("d3fend_technique_id", None)
        entry.pop("d3fend_technique_name", None)

    impacts = conn.execute(
        "SELECT metric, from_value, to_value, rationale FROM cvss_vector_impacts WHERE cme_id = %(id)s",
        {"id": cme_id},
    ).fetchall()
    entry["cvss_vector_impacts"] = [
        {"metric": r["metric"], "from": r["from_value"], "to": r["to_value"], "rationale": r["rationale"]}
        for r in impacts
    ]

    cwes = conn.execute(
        "SELECT cwe_id FROM cwe_relationships WHERE cme_id = %(id)s", {"id": cme_id}
    ).fetchall()
    entry["cwe_relationships"] = [r["cwe_id"] for r in cwes]

    vcmds = conn.execute(
        "SELECT method, command, expected, platform FROM verification_commands WHERE cme_id = %(id)s",
        {"id": cme_id},
    ).fetchall()
    if vcmds:
        entry["verification"] = {
            "method": vcmds[0]["method"],
            "commands": [{"command": r["command"], "expected": r["expected"], "platform": r["platform"]} for r in vcmds],
        }

    refs = conn.execute(
        "SELECT source, url, section FROM references_ WHERE cme_id = %(id)s", {"id": cme_id}
    ).fetchall()
    if refs:
        entry["references"] = [dict(r) for r in refs]

    return entry
