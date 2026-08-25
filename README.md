# ExecCheck

ExecCheck is an offline macOS forensic triage tool for the Gatekeeper/System
Policy `ExecPolicy` SQLite database. It parses, correlates, scores, and exports
evidence from:

- `executable_measurements_v2`
- `policy_scan_cache`
- `provenance_tracking`

ExecCheck is a prioritization aid, not a malware verdict. Scores identify
configured review signals and must be validated against the retained evidence.

## Forensic handling

SIP protects the live database at
`/var/db/SystemPolicyConfiguration/ExecPolicy`. Analyze an acquired copy or a
mounted volume, and acquire `ExecPolicy-wal` and `ExecPolicy-shm` with the main
database when they exist. ExecCheck copies the supplied database and companion
files to a temporary analysis snapshot before opening SQLite, preventing SQLite
from creating or updating sidecars beside the source artifact.

ExecCheck follows these evidence rules:

- `UNKNOWN` is distinct from observed `False`.
- A missing source row is an evidence gap, not negative evidence.
- Values observed in scan or provenance tables remain available even when no
  executable-measurement row exists.
- Quarantine/Gatekeeper processing, alerts, user approval, and successful
  evaluation are context; they are not independently scored as malicious.
- Unmapped Apple enums and flag bits keep their raw numeric values and are not
  assigned undocumented meanings.
- Timestamp proximity is not used as evidence of identity or causation.

## Correlation and data model

CDHash is the primary correlation key. A row without a CDHash may join an
existing CDHash group by `file_identifier` only when that identifier maps to one
and only one group. Otherwise it remains a separate low-confidence fallback
record. ExecCheck does not correlate records by similar timestamps.

Every combined result includes:

- `correlation`: key type, key, confidence, and contributing sources
- `source_tables` and `source_counts`
- `source_records`: every raw contributing row from each supported table
- `field_provenance`: canonical field state, value sources, and sources that
  explicitly stored null
- `field_conflicts`: all observed values and their sources when sources disagree
- `origin_urls` and timestamped `origin_observations`
- `uncertainty_reasons`, `evidence_quality`, and source completeness

Canonical fields have four meaningful states: observed true/value, observed
false, unknown/not observed, and conflicting. A value present in one source is
not erased by null or absence in another. When non-null sources conflict, the
canonical field is null, all values are exposed in `field_conflicts`, and
correlation confidence is downgraded.

Legacy singular fields such as `origin_url`, `scan_timestamp`, and
`correlation_type` remain for compatibility. JSON and NDJSON retain the complete
nested evidence model. CSV stores lists and objects as JSON strings within cells.

## Scoring

Default scoring is tri-state safe:

- `unsigned` applies only when `is_signed is False`; missing or null does not
  score.
- `missing_team_id` applies only to an explicitly observed null Team ID, not when
  the necessary source was unavailable.
- `override_blocked` requires an explicit `Override: Block` label. Numeric Apple
  policy value `3` is not assumed to mean a block.
- VirusTotal scoring applies only to an affirmative malicious result returned by
  the optional enrichment; request failures and incomplete responses remain
  unknown rather than becoming false clean results.
- `custom_flag_mask` is empty by default. Organization-specific flag scoring is
  opt-in and should be accompanied by an internally documented rationale.

Evidence gaps appear in `uncertainty_reasons`; they do not add malicious-risk
points.

### Allowlists

Configured hashes, Team IDs, and paths create visible `allowlist_matches`; no
record or source evidence is deleted. Exact hash/Team-ID matching is
case-insensitive. Paths support shell-style patterns.

- A hash or path match suppresses `unsigned`, `missing_team_id`, and custom flag
  heuristics.
- A Team-ID match suppresses `missing_team_id` and custom flag heuristics.
- Explicit block and VirusTotal malicious signals are never suppressed.

Applied suppressions are listed in `allowlist_suppressed_rules`.

### Output configuration

`output.min_score` is enforced for table, CSV, JSON, and NDJSON. Entries in
`output.filters` are AND-combined. A scalar requires an exact field match; a list
accepts any listed value. Two evidence-aware aliases are supported:
`team_id_missing` matches only an observed-null Team ID, and `blocked` matches
only the explicit `Override: Block` label. The supplied configuration leaves
filters empty and uses a minimum score of zero.

## Requirements and installation

ExecCheck requires Python 3.10 or newer. Python 3.12 is the preferred
development/runtime version; CI tests Python 3.10, 3.11, 3.12, and 3.13 on
macOS. Python 3.9 is not supported.

Install a current Python from [python.org](https://www.python.org/downloads/),
Homebrew, or another user-managed Python distribution. Do not modify, delete,
or replace Apple's system Python, and do not rely on Xcode's bundled Python for
the project environment.

```bash
git clone https://github.com/nybblebytes/ExecCheck.git
cd ExecCheck
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`pyproject.toml` is the authoritative project metadata and declares
`requires-python = ">=3.10"`. Runtime dependencies use bounded compatibility
ranges: minimum versions provide the APIs tested by ExecCheck and upper bounds
prevent an unreviewed future major release. `requirements.txt` installs the
local project and those declared dependencies, avoiding a second dependency
list that can drift.

The package also checks the interpreter at startup. Running directly from a
source tree on an unsupported interpreter produces a clear version error rather
than failing later while evaluating type annotations.

## Usage

```bash
# Terminal triage
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --output-format table

# Table risk bands
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --output-format table high

# Structured export
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --output-format csv --output-path ./results.csv
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --output-format json --output-path ./results.json
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --output-format ndjson --output-path ./results.ndjson

# IOC matching
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --ioc iocs.txt --only-ioc-matches

# Optional VirusTotal enrichment (requires vt_api_key in the configuration)
python -m execcheck --db /path/to/ExecPolicy --config sample_config.yaml --vt --output-format json --output-path results.json
```

`--output-format` accepts exactly one format per invocation. `--output-path`
expects a file path, not a directory. Without it, CSV, JSON, and NDJSON are
written to stdout. VirusTotal hash submissions may become public unless your
license provides private submission; review that exposure before enabling
`--vt`.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q

# Optional integration test against an acquired database
EXECCHECK_REGRESSION_DB=/path/to/ExecPolicy python -m pytest -q tests/test_real_execpolicy.py
```

Unknown Apple values intentionally remain unmapped until a reliable source is
available. Preserve their raw codes when sharing results so future research can
reinterpret the original evidence.
