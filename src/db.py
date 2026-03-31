"""CME Database layer — SQLite storage for the Common Mitigation Enumeration taxonomy."""

import json
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "cme.db"


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cme_entries (
            cme_id          TEXT PRIMARY KEY,
            control_name    TEXT NOT NULL,
            description     TEXT NOT NULL,
            tactic          TEXT NOT NULL CHECK(tactic IN ('Harden','Isolate','Detect','Evict','Restore')),
            category        TEXT NOT NULL,
            control_layer   TEXT NOT NULL CHECK(control_layer IN ('Network','OS/Kernel','Application','Data','Identity')),
            confidence      TEXT CHECK(confidence IN ('High','Medium','Low')),
            platforms_json  TEXT,   -- JSON array
            d3fend_technique_id   TEXT,
            d3fend_technique_name TEXT
        );

        CREATE TABLE IF NOT EXISTS cvss_vector_impacts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            metric      TEXT NOT NULL CHECK(metric IN ('AV','AC','PR','UI','S','C','I','A')),
            from_value  TEXT NOT NULL,
            to_value    TEXT NOT NULL,
            rationale   TEXT
        );

        CREATE TABLE IF NOT EXISTS cwe_relationships (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            cwe_id  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verification_commands (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            method      TEXT,
            command     TEXT NOT NULL,
            expected    TEXT NOT NULL,
            platform    TEXT DEFAULT 'linux'
        );

        CREATE TABLE IF NOT EXISTS references_ (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            source  TEXT NOT NULL,
            url     TEXT,
            section TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_entries_tactic ON cme_entries(tactic);
        CREATE INDEX IF NOT EXISTS idx_entries_layer ON cme_entries(control_layer);
        CREATE INDEX IF NOT EXISTS idx_entries_category ON cme_entries(category);
        CREATE INDEX IF NOT EXISTS idx_cvss_cme ON cvss_vector_impacts(cme_id);
        CREATE INDEX IF NOT EXISTS idx_cwe_cme ON cwe_relationships(cme_id);
        CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_relationships(cwe_id);
    """)


def insert_entry(conn: sqlite3.Connection, entry: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO cme_entries
           (cme_id, control_name, description, tactic, category, control_layer,
            confidence, platforms_json, d3fend_technique_id, d3fend_technique_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            entry["cme_id"],
            entry["control_name"],
            entry["description"],
            entry["tactic"],
            entry["category"],
            entry["control_layer"],
            entry.get("confidence"),
            json.dumps(entry.get("platforms", [])),
            entry.get("d3fend_mapping", {}).get("technique_id"),
            entry.get("d3fend_mapping", {}).get("technique_name"),
        ),
    )

    # Clear child rows for upsert
    for table in ("cvss_vector_impacts", "cwe_relationships", "verification_commands", "references_"):
        conn.execute(f"DELETE FROM {table} WHERE cme_id = ?", (entry["cme_id"],))

    for impact in entry.get("cvss_vector_impacts", []):
        conn.execute(
            """INSERT INTO cvss_vector_impacts (cme_id, metric, from_value, to_value, rationale)
               VALUES (?, ?, ?, ?, ?)""",
            (entry["cme_id"], impact["metric"], impact["from"], impact["to"], impact.get("rationale")),
        )

    for cwe in entry.get("cwe_relationships", []):
        conn.execute(
            "INSERT INTO cwe_relationships (cme_id, cwe_id) VALUES (?, ?)",
            (entry["cme_id"], cwe),
        )

    verification = entry.get("verification", {})
    method = verification.get("method")
    for cmd in verification.get("commands", []):
        conn.execute(
            """INSERT INTO verification_commands (cme_id, method, command, expected, platform)
               VALUES (?, ?, ?, ?, ?)""",
            (entry["cme_id"], method, cmd["command"], cmd["expected"], cmd.get("platform", "linux")),
        )

    for ref in entry.get("references", []):
        conn.execute(
            "INSERT INTO references_ (cme_id, source, url, section) VALUES (?, ?, ?, ?)",
            (entry["cme_id"], ref["source"], ref.get("url"), ref.get("section")),
        )


# --- Query helpers ---

def get_entry(conn: sqlite3.Connection, cme_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cme_entries WHERE cme_id = ?", (cme_id,)).fetchone()
    if not row:
        return None
    return _hydrate(conn, dict(row))


def search_entries(
    conn: sqlite3.Connection,
    *,
    tactic: str | None = None,
    category: str | None = None,
    control_layer: str | None = None,
    keyword: str | None = None,
) -> list[dict]:
    clauses = []
    params: list = []
    if tactic:
        clauses.append("tactic = ?")
        params.append(tactic)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if control_layer:
        clauses.append("control_layer = ?")
        params.append(control_layer)
    if keyword:
        clauses.append("(control_name LIKE ? OR description LIKE ?)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    where = " AND ".join(clauses) if clauses else "1=1"
    rows = conn.execute(f"SELECT * FROM cme_entries WHERE {where} ORDER BY cme_id", params).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_mitigations_for_cwe(conn: sqlite3.Connection, cwe_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT e.* FROM cme_entries e
           JOIN cwe_relationships c ON e.cme_id = c.cme_id
           WHERE c.cwe_id = ?
           ORDER BY e.cme_id""",
        (cwe_id,),
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_attenuation_for_cve(
    conn: sqlite3.Connection,
    active_cme_ids: list[str],
) -> list[dict]:
    """Given a list of active CME-IDs, return all CVSS vector impacts."""
    if not active_cme_ids:
        return []
    placeholders = ",".join("?" for _ in active_cme_ids)
    rows = conn.execute(
        f"""SELECT e.cme_id, e.control_name, v.metric, v.from_value, v.to_value, v.rationale
            FROM cme_entries e
            JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
            WHERE e.cme_id IN ({placeholders})
            ORDER BY e.cme_id, v.metric""",
        active_cme_ids,
    ).fetchall()
    return [dict(r) for r in rows]


def list_tactics(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT tactic, COUNT(*) as count FROM cme_entries GROUP BY tactic ORDER BY tactic"
    ).fetchall()
    return [dict(r) for r in rows]


def list_categories(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT tactic, category, control_layer, COUNT(*) as count
           FROM cme_entries GROUP BY tactic, category, control_layer
           ORDER BY tactic, category"""
    ).fetchall()
    return [dict(r) for r in rows]


def _hydrate(conn: sqlite3.Connection, entry: dict) -> dict:
    cme_id = entry["cme_id"]
    entry["platforms"] = json.loads(entry.pop("platforms_json") or "[]")

    if entry.get("d3fend_technique_id"):
        entry["d3fend_mapping"] = {
            "technique_id": entry.pop("d3fend_technique_id"),
            "technique_name": entry.pop("d3fend_technique_name"),
        }
    else:
        entry.pop("d3fend_technique_id", None)
        entry.pop("d3fend_technique_name", None)

    impacts = conn.execute(
        "SELECT metric, from_value, to_value, rationale FROM cvss_vector_impacts WHERE cme_id = ?",
        (cme_id,),
    ).fetchall()
    entry["cvss_vector_impacts"] = [
        {"metric": r["metric"], "from": r["from_value"], "to": r["to_value"], "rationale": r["rationale"]}
        for r in impacts
    ]

    cwes = conn.execute("SELECT cwe_id FROM cwe_relationships WHERE cme_id = ?", (cme_id,)).fetchall()
    entry["cwe_relationships"] = [r["cwe_id"] for r in cwes]

    vcmds = conn.execute(
        "SELECT method, command, expected, platform FROM verification_commands WHERE cme_id = ?",
        (cme_id,),
    ).fetchall()
    if vcmds:
        entry["verification"] = {
            "method": vcmds[0]["method"],
            "commands": [{"command": r["command"], "expected": r["expected"], "platform": r["platform"]} for r in vcmds],
        }

    refs = conn.execute("SELECT source, url, section FROM references_ WHERE cme_id = ?", (cme_id,)).fetchall()
    if refs:
        entry["references"] = [dict(r) for r in refs]

    return entry
