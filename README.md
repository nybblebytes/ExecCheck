# ExecCheck

Tested on Sonoma 14.7.6

**ExecCheck** is a macOS forensic analysis tool designed to parse, score, correlate, and triage data from the `ExecPolicy` database (`/var/db/SystemPolicyConfiguration/ExecPolicy`). It enables security teams and investigators to extract actionable intelligence from Gatekeeper and system policy telemetry.

This tool is a POC intended to enable others to explore and streamline workflows.

⚠️ Important: ExecPolicy data is protected by SIP and can not be queried live therefore ExecCheck is an offline analyzer; it can not access the db on a live system, you need to either make a copy or run it against a mounted volume. With FullDiskAccess (FDA), you can sudo cp /private/var/db/SystemPolicyConfiguration/ExecPolicy /path/to/destination/ExecPolicy* (do not forget the shm and wal) or in an enterprise scenario you can use your MDM or EDR (with proper entitlements)

---

## Tool Overview

**ExecCheck** helps investigators and enterprise defenders:

- Investigate application and binary execution metadata
- Detect suspicious, unsigned, or quarantined files
- Identify binaries from unknown teams or volumes
- Score each binary based on risk attributes (e.g., unsigned, VT flagged)
- Cross-reference against new threat intel (IOC matching)
- Export triage-ready results for incident response or SIEM ingestion

**ExecCheck** automatically parses and correlates (from cdhash) records from:

- executable_measurements_v2
- policy_scan_cache
- provenance_tracking

**ExecCheck** supports:

- Risk scoring logic (customizable heuristics via yaml config file). Each record gets a risk_score (numerical severity) and score_trace (which rules and why)
  - Unsigned status
  - Missing or untrusted team ID
  - Gatekeeper override flags
  - Revoked or weak certificates
  - Malicious VT results (optional)
  - External volume origin

- Feeding threat intel to scan for known indicators (via --ioc ioc.txt)
  - Simple list of IOCs (one per line)
  - Matches across all fields
  - Tracks which fields matched per record

- VirusTotal hash enrichment (via --vt). Remember that what you upload is public unless you have an enterprise license.
  - add API key to config.yaml
  - will send all executable hashes (sha256), fetch the results and factor results as risk weights

- Customization through a YAML config file
  - customize scoring based on database fields
  - allowlist of hashes, team ids, and paths
  - customize output filters
  - customize color thresholds

- Output formats: CSV, JSON, NDJSON, rich terminal
  - terminal table
    - output in terminal in rich table view
    - choose which risk category you want to view or all of them
    - table is limited to only risk_score, score_trace (reason for risk score), file_identifier, responsible_file_identifier, and origin_url
    - customize to your own needs
  - csv
    - full parsing, scoring, collated tables as csv (for humans)
  - json
    - full parsing, scoring, collated tables as json (for machines)
  - ndjson
    - full parsing, scoring, collated tables as ndjson (for SIEM)

- Auto mapping to known flags and auto time conversion to human readable (iso)

---
## Integration Use Cases

**ExecCheck** is designed for flexible deployment:
- Hunt Operations: Feed NDJSON into Splunk or Elastic with minimal parsing.
- Threat Intel / IOC Matching: Check against known indicators during investigations (ingestion) or feeding ExecCheck's ndjson outputs to SIEM or both.
- Incident Response: Suspicious executable.
- Historical Analysis: Determine if an executable was presence on disk or possible executed.

⚠️ Important: Always validate results using additional context—ExecCheck scores and correlations are designed to prioritize review, not replace human judgment.

## Getting Started
```bash
# Downloading
git clone git@github.com/nybblebytes/ExecCheck.git
cd /path/to/ExecCheck

# Setting up enviroment using Python 3.9 to 3.11
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```
## Sample Commands
```
# Basic triage
python3 -m execcheck --db /path/to/ExecPolicy --config /path/to/config.yaml --output-format table

# Filter for unsigned binaries with low/med/high score
python3 -m execcheck --db ./ExecPolicy --config /path/to/config.yaml --output-format table [all|low|med|high]

# Save output to CSV, JSON, NDJSON
python3 -m execcheck --db ./ExecPolicy --config /path/to/config.yaml --output-format csv/json/ndjson --output-path /path/to/destination

# IOC matching
python3 -m execcheck --db ./ExecPolicy --ioc /path/to/list.txt --only-ioc-matches

# VirusTotal hash enrichment. Requires VT API Key in config.yaml
python3 -m execcheck --db ./ExecPolicy --vt --output-format html
```
