import sqlite3

from execcheck.combine import combine_exec_policy_tables


def make_database(tmp_path, exec_rows=(), scan_rows=(), provenance_rows=()):
    path = tmp_path / "ExecPolicy"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE executable_measurements_v2 (
            cdhash TEXT, file_identifier TEXT, bundle_identifier TEXT,
            team_identifier TEXT, signing_identifier TEXT,
            main_executable_hash TEXT, is_signed INTEGER, is_valid INTEGER,
            is_quarantined INTEGER, timestamp INTEGER
        );
        CREATE TABLE policy_scan_cache (
            pk INTEGER, cdhash TEXT, file_identifier TEXT, bundle_id TEXT,
            team_identifier TEXT, signing_identifier TEXT, policy_match INTEGER,
            malware_result INTEGER, flags INTEGER, timestamp INTEGER,
            revocation_check_time INTEGER, volume_uuid TEXT
        );
        CREATE TABLE provenance_tracking (
            pk INTEGER, url TEXT, file_identifier TEXT, bundle_id TEXT,
            cdhash TEXT, team_identifier TEXT, signing_identifier TEXT,
            flags INTEGER, timestamp INTEGER, link_pk INTEGER
        );
        """
    )
    conn.executemany(
        "INSERT INTO executable_measurements_v2 VALUES (?,?,?,?,?,?,?,?,?,?)", exec_rows
    )
    conn.executemany(
        "INSERT INTO policy_scan_cache VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", scan_rows
    )
    conn.executemany(
        "INSERT INTO provenance_tracking VALUES (?,?,?,?,?,?,?,?,?,?)", provenance_rows
    )
    conn.commit()
    conn.close()
    return path


def test_scan_context_survives_without_executable_measurement(tmp_path):
    path = make_database(
        tmp_path,
        scan_rows=[
            (1, "HASH", None, "com.example.app", "TEAM", "com.example.app", 4, 1, 0x2206, 10, 11, "VOL")
        ],
    )
    row = combine_exec_policy_tables(str(path))[0]
    assert row["cdhash"] == "hash"
    assert row["team_identifier"] == "TEAM"
    assert row["signing_identifier"] == "com.example.app"
    assert row["bundle_identifier"] == "com.example.app"
    assert row["is_signed"] is None
    assert row["field_provenance"]["is_signed"]["state"] == "unknown"
    assert row["source_counts"]["executable_measurements_v2"] == 0
    assert row["field_provenance"]["team_identifier"]["sources"] == ["policy_scan_cache"]


def test_analysis_does_not_create_sqlite_sidecars_beside_evidence(tmp_path):
    path = make_database(
        tmp_path,
        exec_rows=[("HASH", "/app", "id", "TEAM", "id", "sha", 1, 1, 0, 10)],
    )
    combine_exec_policy_tables(str(path))
    assert not (tmp_path / "ExecPolicy-wal").exists()
    assert not (tmp_path / "ExecPolicy-shm").exists()


def test_provenance_context_and_multiple_observations_are_preserved(tmp_path):
    path = make_database(
        tmp_path,
        provenance_rows=[
            (2, "/Applications/App.app", None, "app.id", "HASH", "TEAM", "app.id", 2, 20, 1),
            (1, "/Downloads/App.app", None, "app.id", "HASH", "TEAM", "app.id", 2, 10, 0),
        ],
    )
    row = combine_exec_policy_tables(str(path))[0]
    assert row["team_identifier"] == "TEAM"
    assert row["field_provenance"]["team_identifier"]["sources"] == ["provenance_tracking"]
    assert row["origin_urls"] == ["/Downloads/App.app", "/Applications/App.app"]
    assert [item["timestamp"] for item in row["origin_observations"]] == [10, 20]
    assert len(row["source_records"]["provenance_tracking"]) == 2


def test_cdhash_and_file_identifier_do_not_duplicate_artifact(tmp_path):
    path = make_database(
        tmp_path,
        exec_rows=[("HASH", "/app", "id", "TEAM", "id", "sha", 1, 1, 0, 10)],
        scan_rows=[(1, "HASH", "/app", "id", "TEAM", "id", 1, 0, 0, 11, None, "VOL")],
    )
    rows = combine_exec_policy_tables(str(path))
    assert len(rows) == 1
    assert rows[0]["correlation"] == {
        "key_type": "cdhash",
        "key": "hash",
        "confidence": "high",
        "sources": ["executable_measurements_v2", "policy_scan_cache"],
    }


def test_unique_file_identifier_is_only_a_fallback(tmp_path):
    path = make_database(
        tmp_path,
        exec_rows=[("HASH", "/app", "id", "TEAM", "id", "sha", 1, 1, 0, 10)],
        provenance_rows=[(1, "/app", "/app", "id", None, "TEAM", "id", 0, 11, 0)],
    )
    row = combine_exec_policy_tables(str(path))[0]
    assert row["source_counts"]["provenance_tracking"] == 1
    assert row["correlation"]["key_type"] == "cdhash"
    assert len(combine_exec_policy_tables(str(path))) == 1


def test_conflicting_source_values_are_surfaced_and_not_selected(tmp_path):
    path = make_database(
        tmp_path,
        scan_rows=[(1, "HASH", None, "id", "TEAM-A", "id", 1, 0, 0, 10, None, "VOL")],
        provenance_rows=[(1, "/app", None, "id", "HASH", "TEAM-B", "id", 0, 11, 0)],
    )
    row = combine_exec_policy_tables(str(path))[0]
    assert row["team_identifier"] is None
    assert row["field_provenance"]["team_identifier"]["state"] == "conflicting"
    assert {item["value"] for item in row["field_conflicts"]["team_identifier"]["values"]} == {
        "TEAM-A",
        "TEAM-B",
    }
    assert row["correlation"]["confidence"] == "medium"


def test_null_in_one_source_does_not_erase_observed_value(tmp_path):
    path = make_database(
        tmp_path,
        scan_rows=[(1, "HASH", None, "id", None, "id", 1, 0, 0, 10, None, "VOL")],
        provenance_rows=[(1, "/app", None, "id", "HASH", "TEAM", "id", 0, 11, 0)],
    )
    row = combine_exec_policy_tables(str(path))[0]
    assert row["team_identifier"] == "TEAM"
    provenance = row["field_provenance"]["team_identifier"]
    assert provenance["state"] == "observed"
    assert provenance["observed_null_sources"] == ["policy_scan_cache"]
