import os

import pytest

from execcheck.cli import enrich_row
from execcheck.combine import combine_exec_policy_tables
from execcheck.config import Config


REGRESSION_CDHASH = "7dc391cf817b22832831e3aa9f5bf9449b398d3e"


@pytest.mark.skipif(
    not os.environ.get("EXECCHECK_REGRESSION_DB"),
    reason="set EXECCHECK_REGRESSION_DB to run the supplied-evidence integration test",
)
def test_github_desktop_record_does_not_manufacture_suspicious_evidence():
    rows = combine_exec_policy_tables(os.environ["EXECCHECK_REGRESSION_DB"])
    row = next(item for item in rows if item.get("cdhash") == REGRESSION_CDHASH)
    enrich_row(row, Config())

    assert row["team_identifier"] == "VEKTX9H2N7"
    assert row["signing_identifier"] == "com.github.GitHubClient"
    assert row["bundle_identifier"] == "com.github.GitHubClient"
    assert set(row["source_tables"]) == {"policy_scan_cache", "provenance_tracking"}
    assert row["source_counts"]["executable_measurements_v2"] == 0
    assert row["source_counts"]["policy_scan_cache"] == 1
    assert row["source_counts"]["provenance_tracking"] == 2
    assert row["is_signed"] is None
    assert not any("unsigned" in item for item in row["score_trace"])
    assert not any("missing_team_id" in item for item in row["score_trace"])
    assert row["origin_urls"] == [
        "/Users/zugzwang/Downloads/GitHub Desktop.app",
        "/Applications/GitHub Desktop.app",
    ]
    assert row["malware_result"] == 1
    assert row["malware_result_label"] == "Unmapped (code=1)"
    assert row["flags_decoded_policy"]["unknown_flag_mask"] == 0x2000
    assert row["risk_score"] == 0
