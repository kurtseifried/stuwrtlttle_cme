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


def main():
    schema = load_schema()
    validator = Draft202012Validator(schema)

    entries_dir = Path(__file__).parent.parent / "data" / "entries"
    files = sorted(entries_dir.glob("CME-*.json"))

    if not files:
        print("No entry files found.")
        sys.exit(1)

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

        # Check for duplicate IDs
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

    print(f"\nValidated {len(files)} entries.")
    if errors_found:
        print("Some entries have errors.")
        sys.exit(1)
    else:
        print("All entries valid.")


if __name__ == "__main__":
    main()
