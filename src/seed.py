"""Seed the CME database from individual entry JSON files."""

import json
from pathlib import Path

from .db import DEFAULT_DB_PATH, get_connection, init_db, insert_entry

ENTRIES_DIR = Path(__file__).parent.parent / "data" / "entries"


def main():
    # Remove existing DB to rebuild fresh
    if DEFAULT_DB_PATH.exists():
        DEFAULT_DB_PATH.unlink()

    conn = get_connection(DEFAULT_DB_PATH)
    init_db(conn)

    count = 0
    for path in sorted(ENTRIES_DIR.glob("CME-*.json")):
        with open(path) as f:
            entry = json.load(f)
        insert_entry(conn, entry)
        count += 1

    conn.commit()
    conn.close()
    print(f"Seeded {count} CME entries into {DEFAULT_DB_PATH}")


if __name__ == "__main__":
    main()
