"""Validate CME entry files against the JSON schema."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


def load_schema() -> dict:
    schema_path = Path(__file__).parent.parent / "schema" / "cme-entry.schema.json"
    with open(schema_path) as f:
        return json.load(f)


def validate_entry(entry: dict, validator: Draft202012Validator) -> list[str]:
    return [e.message for e in validator.iter_errors(entry)]


def validate_dir(files: list[Path], validator: Draft202012Validator) -> tuple[bool, dict[str, str]]:
    """Validate a set of CME JSON files against the schema, checking filename↔cme_id
    match and duplicate IDs within the set. Returns (errors_found, {cme_id: filename})."""
    errors_found = False
    seen_ids: dict[str, str] = {}

    for path in files:
        with open(path) as f:
            entry = json.load(f)

        # Check filename matches cme_id
        expected_id = path.stem
        if entry.get("cme_id") != expected_id:
            print(f"FAIL {path.name}: cme_id '{entry.get('cme_id')}' does not match filename '{expected_id}'")
            errors_found = True

        # Check for duplicate IDs within this directory
        cme_id = entry.get("cme_id", "unknown")
        if cme_id in seen_ids:
            print(f"FAIL {path.name}: duplicate cme_id '{cme_id}' (also in {seen_ids[cme_id]})")
            errors_found = True
        seen_ids[cme_id] = path.name

        # Schema validation
        errs = validate_entry(entry, validator)
        if errs:
            errors_found = True
            for e in errs:
                print(f"FAIL {path.name}: {e}")
        else:
            print(f"  OK {path.name}")

    return errors_found, seen_ids


def main():
    schema = load_schema()
    validator = Draft202012Validator(schema)

    data_dir = Path(__file__).parent.parent / "data"
    entry_files = sorted((data_dir / "entries").glob("CME-*.json"))
    proposal_files = sorted((data_dir / "proposals").glob("CME-*.json"))

    if not entry_files:
        print("No entry files found.")
        sys.exit(1)

    errors_found = False

    print(f"Validating {len(entry_files)} entries in data/entries/ ...")
    entry_errors, entry_ids = validate_dir(entry_files, validator)
    errors_found |= entry_errors

    if proposal_files:
        print(f"\nValidating {len(proposal_files)} proposals in data/proposals/ ...")
        proposal_errors, proposal_ids = validate_dir(proposal_files, validator)
        errors_found |= proposal_errors

        # A proposal whose ID already exists as a live entry is an orphan: approval
        # via approve_cme_proposal removes the proposal, so a leftover means it was
        # approved by hand and the stale proposal should be deleted.
        for cme_id, fname in proposal_ids.items():
            if cme_id in entry_ids:
                print(
                    f"FAIL {fname}: proposal '{cme_id}' already exists as a live entry "
                    f"({entry_ids[cme_id]}) — delete the stale proposal (or re-approve via the tool)"
                )
                errors_found = True

    summary = f"Validated {len(entry_files)} entries"
    if proposal_files:
        summary += f" and {len(proposal_files)} proposals"
    print(f"\n{summary}.")

    if errors_found:
        print("Some files have errors.")
        sys.exit(1)
    else:
        print("All files valid.")


if __name__ == "__main__":
    main()
