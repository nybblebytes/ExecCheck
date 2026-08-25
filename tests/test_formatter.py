import csv
import json

from execcheck.formatter import output_csv


def test_csv_safely_serialises_nested_evidence(tmp_path):
    path = tmp_path / "result.csv"
    output_csv([{"cdhash": "abc", "source_counts": {"scan": 1}, "origin_urls": ["/app"]}], str(path))
    with path.open(newline="") as file_handle:
        row = next(csv.DictReader(file_handle))
    assert json.loads(row["source_counts"]) == {"scan": 1}
    assert json.loads(row["origin_urls"]) == ["/app"]
