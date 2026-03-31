"""CME MCP Server — exposes the Common Mitigation Enumeration database via MCP tools."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from mcp.server.fastmcp import FastMCP

from . import config

# Select database backend based on configuration
if config.DB_BACKEND == "postgres":
    from . import db_postgres as db
else:
    from . import db as db  # type: ignore[no-redef]

PROJECT_ROOT = Path(__file__).parent.parent
ENTRIES_DIR = PROJECT_ROOT / "data" / "entries"
PROPOSALS_DIR = PROJECT_ROOT / "data" / "proposals"
SCHEMA_PATH = PROJECT_ROOT / "schema" / "cme-entry.schema.json"

mcp = FastMCP(
    "CME — Common Mitigation Enumeration",
    instructions=(
        "A taxonomy of defensive security controls mapped to CVSS vector attenuation. "
        "Query mitigations by ID, tactic, CWE, or keyword. Calculate risk attenuation "
        "for active controls."
    ),
    host=config.HTTP_HOST,
    port=config.HTTP_PORT,
)

_conn = None


def _get_db():
    global _conn
    if _conn is None:
        _conn = db.get_connection()
        db.init_db(_conn)
    return _conn


# --- Query Tools ---


@mcp.tool()
def get_cme_entry(cme_id: str) -> str:
    """Look up a specific CME entry by its ID (e.g., CME-101, CME-602).

    Returns the full entry including description, CVSS vector impacts,
    CWE relationships, verification commands, and references.
    """
    entry = db.get_entry(_get_db(), cme_id.upper())
    if not entry:
        return json.dumps({"error": f"No entry found for {cme_id}"})
    return json.dumps(entry, indent=2)


@mcp.tool()
def search_cme(
    tactic: str = "",
    category: str = "",
    control_layer: str = "",
    keyword: str = "",
) -> str:
    """Search CME entries by tactic, category, control layer, or keyword.

    Args:
        tactic: Filter by D3FEND-aligned tactic (Harden, Isolate, Detect, Evict, Restore)
        category: Filter by sub-category (e.g., "Kernel Hardening", "Network Isolation")
        control_layer: Filter by technology layer (Network, OS/Kernel, Application, Data, Identity)
        keyword: Free-text search across control name and description

    Returns matching CME entries with full details.
    """
    results = db.search_entries(
        _get_db(),
        tactic=tactic or None,
        category=category or None,
        control_layer=control_layer or None,
        keyword=keyword or None,
    )
    return json.dumps(results, indent=2)


@mcp.tool()
def get_mitigations_for_weakness(cwe_id: str) -> str:
    """Find all CME mitigations that address a specific CWE weakness.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-119", "CWE-78", "CWE-269")

    Returns CME entries whose controls mitigate the given weakness class.
    Useful for determining what defenses apply to a vulnerability's root cause.
    """
    cwe = cwe_id.upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    results = db.get_mitigations_for_cwe(_get_db(), cwe)
    if not results:
        return json.dumps({"message": f"No mitigations found for {cwe}", "cwe_id": cwe})
    return json.dumps(results, indent=2)


@mcp.tool()
def calculate_attenuation(active_cme_ids: list[str]) -> str:
    """Calculate CVSS risk attenuation for a set of active CME controls.

    Given a list of CME-IDs that are verified active on a target system,
    returns all CVSS base metric modifications those controls provide.
    This is the core of CME: deterministic environmental scoring.

    Args:
        active_cme_ids: List of active CME identifiers (e.g., ["CME-101", "CME-301", "CME-601"])

    Returns the aggregated CVSS vector modifications, showing how each
    base metric is shifted by the active controls.

    Example usage by an AI agent:
        1. Discover CVE-2026-XXXX on a server
        2. Identify active CME controls on that server
        3. Call this tool to get the attenuation profile
        4. Apply modifications to CVSS base score for environmental score
    """
    ids = [i.upper() for i in active_cme_ids]
    impacts = db.get_attenuation_for_cve(_get_db(), ids)
    if not impacts:
        return json.dumps({"message": "No impacts found for provided CME-IDs", "provided": ids})

    # Aggregate by metric — take the most restrictive (best defense) for each metric
    aggregated: dict[str, dict] = {}
    details = []
    for impact in impacts:
        details.append(impact)
        metric = impact["metric"]
        if metric not in aggregated:
            aggregated[metric] = {
                "metric": metric,
                "modified_to": impact["to_value"],
                "contributing_controls": [impact["cme_id"]],
            }
        else:
            aggregated[metric]["contributing_controls"].append(impact["cme_id"])
            # Keep the more restrictive value
            severity_order = {"N": 0, "L": 1, "A": 2, "P": 3, "U": 4, "H": 5, "C": 6}
            current = severity_order.get(aggregated[metric]["modified_to"], 99)
            new = severity_order.get(impact["to_value"], 99)
            if new < current:
                aggregated[metric]["modified_to"] = impact["to_value"]

    return json.dumps({
        "active_controls": len(ids),
        "aggregated_attenuation": list(aggregated.values()),
        "detail": details,
    }, indent=2)


@mcp.tool()
def list_cme_taxonomy() -> str:
    """List the full CME taxonomy structure — all tactics and categories with entry counts.

    Returns a hierarchical view of the taxonomy for navigation and discovery.
    """
    tactics = db.list_tactics(_get_db())
    categories = db.list_categories(_get_db())
    return json.dumps({"tactics": tactics, "categories": categories}, indent=2)


@mcp.tool()
def get_verification_commands(cme_id: str) -> str:
    """Get the machine-executable verification commands for a specific CME control.

    Returns shell commands that a scanner or agent can run to verify
    whether the control is active on a target system.

    Args:
        cme_id: CME identifier (e.g., "CME-101")
    """
    entry = db.get_entry(_get_db(), cme_id.upper())
    if not entry:
        return json.dumps({"error": f"No entry found for {cme_id}"})
    verification = entry.get("verification", {})
    return json.dumps({
        "cme_id": entry["cme_id"],
        "control_name": entry["control_name"],
        "verification": verification,
    }, indent=2)


@mcp.tool()
def simulate_cve_risk(
    base_score: float,
    base_vector: str,
    active_cme_ids: list[str],
) -> str:
    """Simulate the risk attenuation of a CVE given active CME controls.

    This is the "Risk Negotiation" tool from the CME proposal. Given a CVE's
    base score and CVSS vector string, plus the active controls on the target,
    it shows which metrics would be modified and estimates an attenuated score.

    Args:
        base_score: CVSS base score (e.g., 9.8)
        base_vector: CVSS vector string (e.g., "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        active_cme_ids: List of CME-IDs active on the target system

    Returns the original vs modified vector with estimated attenuation.
    """
    ids = [i.upper() for i in active_cme_ids]
    impacts = db.get_attenuation_for_cve(_get_db(), ids)

    # Parse the base vector
    metrics: dict[str, str] = {}
    for part in base_vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            metrics[k] = v

    modifications = []
    modified_metrics = dict(metrics)
    for impact in impacts:
        metric = impact["metric"]
        if metric in metrics and metrics[metric] == impact["from_value"]:
            modified_metrics[metric] = impact["to_value"]
            modifications.append({
                "cme_id": impact["cme_id"],
                "control_name": impact["control_name"],
                "metric": metric,
                "from": impact["from_value"],
                "to": impact["to_value"],
                "rationale": impact["rationale"],
            })

    # Reconstruct modified vector
    prefix = base_vector.split("/")[0] if "/" in base_vector else "CVSS:4.0"
    modified_vector = prefix + "/" + "/".join(f"{k}:{v}" for k, v in modified_metrics.items())

    return json.dumps({
        "original": {
            "score": base_score,
            "vector": base_vector,
        },
        "active_controls": len(ids),
        "modifications_applied": len(modifications),
        "modifications": modifications,
        "modified_vector": modified_vector,
        "note": "Estimated attenuated score requires full CVSS calculator. The modified vector can be fed into any CVSS v4.0 calculator to get the environmental score.",
    }, indent=2)


# --- Curation Tools ---


def _load_schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def _next_cme_id(category_prefix: int) -> str:
    """Find the next available CME-ID in a given number range."""
    conn = _get_db()
    prefix_str = str(category_prefix // 100)
    if config.DB_BACKEND == "postgres":
        rows = conn.execute(
            "SELECT cme_id FROM cme_entries WHERE cme_id LIKE %(pat)s ORDER BY cme_id",
            {"pat": f"CME-{prefix_str}%"},
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT cme_id FROM cme_entries WHERE cme_id LIKE ? ORDER BY cme_id",
            (f"CME-{prefix_str}%",),
        ).fetchall()
    if not rows:
        return f"CME-{category_prefix}"
    max_num = max(int(r["cme_id"].split("-")[1]) for r in rows)
    return f"CME-{max_num + 1}"


@mcp.tool()
def propose_cme_entry(
    control_name: str,
    description: str,
    tactic: str,
    category: str,
    control_layer: str,
    cvss_impacts_json: str,
    cwe_ids: list[str] = [],
    verification_method: str = "",
    verification_commands_json: str = "[]",
    platforms: list[str] = [],
    confidence: str = "Medium",
) -> str:
    """Propose a new CME entry for review.

    Creates a proposal JSON file in the proposals directory. The entry is
    validated against the CME schema but NOT added to the live database
    until reviewed and approved.

    Args:
        control_name: Formal name (e.g., "Kernel-Level Syscall Filtering (seccomp)")
        description: Technical description of what the control does
        tactic: D3FEND tactic (Harden, Isolate, Detect, Evict, Restore)
        category: Sub-category (e.g., "Kernel Hardening", "Network Isolation")
        control_layer: Technology layer (Network, OS/Kernel, Application, Data, Identity)
        cvss_impacts_json: JSON array of impacts, e.g. [{"metric":"AC","from":"L","to":"H","rationale":"..."}]
        cwe_ids: List of CWE IDs this mitigates (e.g., ["CWE-119", "CWE-78"])
        verification_method: Human-readable verification description
        verification_commands_json: JSON array of commands, e.g. [{"command":"cat /proc/...","expected":"2","platform":"linux"}]
        platforms: Applicable platforms (e.g., ["RHEL 9", "Ubuntu 24.04"])
        confidence: Confidence level (High, Medium, Low)

    Returns the proposed entry with a suggested CME-ID and file path.
    """
    category_ranges = {
        "Kernel Hardening": 101, "Network Isolation": 201,
        "Mandatory Access Control": 301, "Cryptographic Controls": 401,
        "Filesystem Hardening": 501, "Syscall & BPF Controls": 601,
        "Container Isolation": 701, "Privilege Isolation": 707,
        "Credential Hardening": 801, "Protocol Hardening": 901,
        "Application Controls": 904, "Runtime Detection": 1001,
        "Integrity Detection": 1004, "Patch Management": 1101,
        "Recovery Controls": 1201,
    }
    prefix = category_ranges.get(category, 101)
    suggested_id = _next_cme_id(prefix)

    try:
        cvss_impacts = json.loads(cvss_impacts_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "cvss_impacts_json is not valid JSON"})

    try:
        verification_commands = json.loads(verification_commands_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "verification_commands_json is not valid JSON"})

    entry = {
        "cme_id": suggested_id,
        "control_name": control_name,
        "description": description,
        "tactic": tactic,
        "category": category,
        "control_layer": control_layer,
        "cvss_vector_impacts": cvss_impacts,
        "cwe_relationships": cwe_ids,
        "confidence": confidence,
        "platforms": platforms,
    }

    if verification_method or verification_commands:
        entry["verification"] = {
            "method": verification_method,
            "commands": verification_commands,
        }

    # Validate against schema
    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = [e.message for e in validator.iter_errors(entry)]
    if errors:
        return json.dumps({
            "status": "validation_failed",
            "errors": errors,
            "entry": entry,
        }, indent=2)

    # Write to proposals directory
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposal_path = PROPOSALS_DIR / f"{suggested_id}.json"
    with open(proposal_path, "w") as f:
        json.dump(entry, f, indent=2)
        f.write("\n")

    return json.dumps({
        "status": "proposed",
        "cme_id": suggested_id,
        "file": str(proposal_path),
        "message": f"Proposal written to {proposal_path}. Review and move to data/entries/ to approve, then re-seed the database.",
        "entry": entry,
    }, indent=2)


@mcp.tool()
def approve_cme_proposal(cme_id: str) -> str:
    """Approve a proposed CME entry — move it from proposals to entries and load into the database.

    Args:
        cme_id: The CME-ID of the proposal to approve (e.g., "CME-114")
    """
    cme_id = cme_id.upper()
    proposal_path = PROPOSALS_DIR / f"{cme_id}.json"
    if not proposal_path.exists():
        return json.dumps({"error": f"No proposal found at {proposal_path}"})

    with open(proposal_path) as f:
        entry = json.load(f)

    # Validate again
    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = [e.message for e in validator.iter_errors(entry)]
    if errors:
        return json.dumps({"error": "Entry fails validation", "details": errors})

    # Move to entries
    entry_path = ENTRIES_DIR / f"{cme_id}.json"
    with open(entry_path, "w") as f:
        json.dump(entry, f, indent=2)
        f.write("\n")
    proposal_path.unlink()

    # Insert into live database
    conn = _get_db()
    db.insert_entry(conn, entry)
    conn.commit()

    return json.dumps({
        "status": "approved",
        "cme_id": cme_id,
        "entry_file": str(entry_path),
        "message": f"{cme_id} is now live in the database and saved to {entry_path}.",
    }, indent=2)


@mcp.tool()
def list_proposals() -> str:
    """List all pending CME entry proposals awaiting review."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposals = []
    for path in sorted(PROPOSALS_DIR.glob("CME-*.json")):
        with open(path) as f:
            entry = json.load(f)
        proposals.append({
            "cme_id": entry["cme_id"],
            "control_name": entry["control_name"],
            "tactic": entry["tactic"],
            "category": entry["category"],
            "file": str(path),
        })
    if not proposals:
        return json.dumps({"message": "No pending proposals."})
    return json.dumps(proposals, indent=2)


# --- Resources ---

@mcp.resource("cme://taxonomy")
def taxonomy_resource() -> str:
    """The full CME taxonomy structure."""
    return list_cme_taxonomy()


@mcp.resource("cme://entry/{cme_id}")
def entry_resource(cme_id: str) -> str:
    """A specific CME entry by ID."""
    return get_cme_entry(cme_id)


@mcp.resource("cme://schema")
def schema_resource() -> str:
    """The CME JSON schema."""
    return SCHEMA_PATH.read_text()


def main():
    mcp.run(transport=config.TRANSPORT)


if __name__ == "__main__":
    main()
