"""Merge data from ExecPolicy tables into unified records."""

import sqlite3
from collections import defaultdict


def combine_exec_policy_tables(db_path: str) -> list[dict]:
    """Return correlated ExecPolicy rows from the given SQLite database."""

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def load_table(query: str) -> list[dict]:
        """Fetch an entire table and return rows as dictionaries."""
        cursor.execute(query)
        return [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]

    exec_rows = load_table("SELECT * FROM executable_measurements_v2")
    scan_rows = load_table("SELECT * FROM policy_scan_cache")
    prov_rows = load_table("SELECT * FROM provenance_tracking")

    conn.close()

    exec_index = defaultdict(list)
    scan_index = defaultdict(list)
    prov_index = defaultdict(list)

    for row in exec_rows:
        cdhash = (row.get("cdhash") or "").strip().lower()
        fid = (row.get("file_identifier") or "").strip().lower()
        if cdhash:
            exec_index[cdhash].append(row)
        if fid:
            exec_index[fid].append(row)

    for row in scan_rows:
        cdhash = (row.get("cdhash") or "").strip().lower()
        fid = (row.get("file_identifier") or "").strip().lower()
        if cdhash:
            scan_index[cdhash].append(row)
        if fid:
            scan_index[fid].append(row)

    for row in prov_rows:
        cdhash = (row.get("cdhash") or "").strip().lower()
        fid = (row.get("file_identifier") or "").strip().lower()
        if cdhash:
            prov_index[cdhash].append(row)
        if fid:
            prov_index[fid].append(row)

    all_keys = set(exec_index.keys()) | set(scan_index.keys()) | set(prov_index.keys())
    combined_rows = []

    for key in all_keys:
        execs = exec_index.get(key, [])
        scans = scan_index.get(key, [])
        provs = prov_index.get(key, [])

        base = execs[0] if execs else {}
        scan = scans[0] if scans else {}
        prov = provs[0] if provs else {}

        row = {}

        row.update(base)

        row["scan_flags"] = scan.get("flags")
        row["malware_result"] = scan.get("malware_result")
        row["policy_match"] = scan.get("policy_match")
        row["scan_timestamp"] = scan.get("timestamp")
        row["revocation_check_time"] = scan.get("revocation_check_time")
        row["volume_uuid"] = scan.get("volume_uuid")
        row["origin_url"] = prov.get("url")
        row["provenance_flags"] = prov.get("flags")
        row["provenance_timestamp"] = prov.get("timestamp")

        row["correlation_type"] = (
            "strong" if execs and scans else
            "weak" if scans or provs else
            "orphan"
        )
        row["correlated_from"] = key

        combined_rows.append(row)

    return combined_rows
