"""Raw scan/provenance indexes for callers that do not need combined rows."""

from collections import defaultdict

from .combine import _connect_read_only, _load_table


def correlate_exec_data(db_path: str) -> tuple[dict, dict]:
    """Return all scan and provenance rows indexed by normalized CDHash.

    No timestamp correlation is attempted, and repeated source observations are
    retained.  Rows without a CDHash remain available through the richer
    :func:`execcheck.combine.combine_exec_policy_tables` API.
    """
    with _connect_read_only(db_path) as conn:
        scan_rows = _load_table(conn, "policy_scan_cache")
        provenance_rows = _load_table(conn, "provenance_tracking")

    scan_data = defaultdict(list)
    provenance_data = defaultdict(list)
    for row in scan_rows:
        cdhash = str(row.get("cdhash") or "").strip().lower()
        if cdhash:
            scan_data[cdhash].append(row)
    for row in provenance_rows:
        cdhash = str(row.get("cdhash") or "").strip().lower()
        if cdhash:
            provenance_data[cdhash].append(row)
    return dict(scan_data), dict(provenance_data)
