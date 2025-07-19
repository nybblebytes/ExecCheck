"""Command-line interface for running ExecCheck."""

import argparse
from .combine import combine_exec_policy_tables
from .scorer import score_entry
from .formatter import output_table, output_csv, output_json, output_ndjson
from .config import load_config
from .vt import query_vt
from .translate import (
    translate_malware_result,
    translate_policy_match,
    decode_flags
)
from .utils.time import to_iso8601


def load_iocs(path: str) -> set[str]:
    """Load indicators of compromise from ``path``."""

    iocs = set()
    with open(path, "r") as f:
        for line in f:
            val = line.strip().lower()
            if val:
                iocs.add(val)
    return iocs

def match_iocs(row: dict, ioc_set: set[str]) -> list[str]:
    """Return a list of fields in ``row`` that matched the IOC set."""

    matched = []
    for k, v in row.items():
        if v is None:
            continue
        if isinstance(v, list):
            v = [str(x).lower() for x in v]
            for ioc in ioc_set:
                if ioc in v:
                    matched.append(k)
        else:
            if str(v).lower() in ioc_set:
                matched.append(k)
    return matched

def main() -> None:
    """Entry point for the ``execcheck`` command."""
    parser = argparse.ArgumentParser(description="ExecCheck with IOC support")
    parser.add_argument(
        "--db",
        required=True,
        help="Path to the extracted ExecPolicy SQLite database",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to YAML configuration file (scoring and output settings)",
    )
    parser.add_argument(
        "--output-format",
        choices=["table", "csv", "json", "ndjson"],
        default="table",
        help="Output format for results",
    )
    parser.add_argument(
        "--output-path",
        required=False,
        help="Optional path to write output (defaults to stdout)",
    )
    parser.add_argument(
        "--ioc",
        help="File containing one IOC per line to match against results",
    )
    parser.add_argument(
        "--only-ioc-matches",
        action="store_true",
        help="Only include records that matched provided IOCs",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Query VirusTotal using the API key defined in the config",
    )
    parser.add_argument(
        "risk_level",
        nargs="?",
        choices=["low", "med", "high", "all"],
        default="all",
        help="Filter table output by risk level when using table format",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    combined_rows = combine_exec_policy_tables(args.db)
    
    vt_data = {}
    if args.vt:
        api_key = config.vt_api_key if hasattr(config, "vt_api_key") else None
        if not api_key:
            print("⚠️  --vt specified but vt_api_key is not set in config. Skipping VT enrichment.")
        else:
            hashes = list({r.get("main_executable_hash") for r in combined_rows if r.get("main_executable_hash")})
            print(f"🔍 Submitting {len(hashes)} hashes to VirusTotal...")
            vt_data = query_vt(hashes, api_key)
            print("✅ VirusTotal enrichment complete.")

    ioc_set = set()
    if args.ioc:
        ioc_set = load_iocs(args.ioc)

    enriched = []
    for row in combined_rows:
        row["malware_result_label"] = translate_malware_result(row.get("malware_result"))
        row["policy_match_label"] = translate_policy_match(row.get("policy_match"))
        row["flags_decoded_policy"] = decode_flags(row.get("scan_flags"))
        row["flags_decoded_provenance"] = decode_flags(row.get("provenance_flags"))
        row["timestamp_iso8601"] = to_iso8601(row.get("timestamp"))
        row["scan_timestamp_iso8601"] = to_iso8601(row.get("scan_timestamp"))
        row["revocation_check_time_iso8601"] = to_iso8601(row.get("revocation_check_time"))
        row["provenance_timestamp_iso8601"] = to_iso8601(row.get("provenance_timestamp"))

        if args.vt and row.get("main_executable_hash") in vt_data:
            row.update(vt_data[row["main_executable_hash"]])

        score, trace = score_entry(row, config)
        row["risk_score"] = score
        row["score_trace"] = trace

        matched_fields = match_iocs(row, ioc_set) if ioc_set else []
        row["ioc_match"] = bool(matched_fields)
        row["matched_fields"] = matched_fields
        enriched.append(row)

    if args.only_ioc_matches:
        enriched = [r for r in enriched if r["ioc_match"]]

    if not enriched:
        print("No matching records.")
        return

    enriched.sort(key=lambda x: x.get("risk_score", 0), reverse=True)


    if args.output_format == "table":
        thresholds = config.dict().get("color_thresholds", {})
        min_yellow = thresholds.get("yellow", 5)
        min_red = thresholds.get("red", 10)

        if args.risk_level == "low":
            enriched = [r for r in enriched if r["risk_score"] < min_yellow]
        elif args.risk_level == "med":
            enriched = [r for r in enriched if min_yellow <= r["risk_score"] < min_red]
        elif args.risk_level == "high":
            enriched = [r for r in enriched if r["risk_score"] >= min_red]

        output_table(enriched, config=config.dict() if hasattr(config, "dict") else dict(config))
        print("✅ Table output complete")
    elif args.output_format == "csv":
        output_csv(enriched, args.output_path)
        print(f"✅ CSV written to {args.output_path}")
    elif args.output_format == "json":
        output_json(enriched, args.output_path)
        print(f"✅ JSON written to {args.output_path}")
    elif args.output_format == "ndjson":
        output_ndjson(enriched, args.output_path)
        print(f"✅ NDJSON written to {args.output_path}")
