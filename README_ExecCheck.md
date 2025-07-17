# ExecCheck

**ExecCheck** is a macOS forensic analysis tool designed to parse, score, correlate, and triage data from the `ExecPolicy` database (`/var/db/SystemPolicyConfiguration/ExecPolicy`). It enables security teams and investigators to extract actionable intelligence from Gatekeeper and system policy telemetry.

---

## 🔍 What It’s For

ExecCheck helps DFIR analysts and enterprise defenders:

- Investigate application and binary execution metadata
- Detect suspicious, unsigned, or quarantined files
- Identify binaries from unknown teams or volumes
- Score each binary based on risk attributes (e.g., unsigned, VT flagged)
- Cross-reference against new threat intel (IOC matching)
- Export triage-ready results for incident response or SIEM ingestion

---

## 🛠 What It Parses

The following tables are parsed and merged from the `ExecPolicy` SQLite database:

- `executable_measurements_v2`
- `policy_scan_cache`
- `provenance_tracking`
- `legacy_exec_history_v4` (if present)

Merging is keyed on `cdhash`, with weak fallback support using `file_identifier`.

---

## 🚫 Cannot Run on Live Systems

**ExecCheck is read-only and designed for offline analysis.**

macOS does not allow live access to the ExecPolicy DB while it is in use by `syspolicyd`.

### ✅ How to Acquire the Database

1. Boot the target Mac into Recovery Mode or use Target Disk Mode
2. Mount the volume externally (e.g., `/Volumes/Macintosh HD`)
3. Copy the following files from the system volume:

```bash
/var/db/SystemPolicyConfiguration/ExecPolicy
/var/db/SystemPolicyConfiguration/ExecPolicy-shm
/var/db/SystemPolicyConfiguration/ExecPolicy-wal
```

4. Provide the path to `ExecPolicy` using the `--db` argument

---

## Installation

Ensure Python 3 is available and install the required packages:

```bash
pip install -r requirements.txt
```

---

## ✨ Features

### ✔️ Risk-Based Scoring

Binaries are scored based on:

- **Unsigned status** — unsigned executables may be ad-hoc or tampered with and
  bypass Apple’s notarization pipeline.
- **Missing or untrusted team ID** — binaries without a trusted team
  identifier often originate from unknown developers.
- **Gatekeeper override flags** — indicates a user or policy has explicitly
  bypassed Gatekeeper protections.
- **Revoked or weak certificates** — code signing certificates revoked by Apple
  or using insecure algorithms are suspicious.
- **Malicious VT results (optional)** — hashes are looked up against
  VirusTotal to see if prior analysis flagged them as malware. Lookups rely on
  the `vt_api_key` you provide in the configuration and respect API rate limits
  by pausing 15 seconds between requests (see `vt.py`).
- **External volume origin** — executables launched from removable or
  network volumes may evade standard quarantine workflows.
- **Custom flag masks** — user-supplied bitmasks can assign scores to unusual
  policy flags, helping surface tampering or overrides that aren’t covered by
  the default rules.

Each record receives:
- `risk_score`: numerical severity
- `score_trace`: which rules triggered and why

### ✔️ Field Correlation

All relevant fields from measurements, scan cache, and provenance are merged, including:

- `cdhash`, `signing_identifier`, `bundle_id`
- `team_identifier`, `volume_uuid`, `origin_url`
- Scan results, flags, and timestamps

### ✔️ IOC Matching

ExecCheck supports feeding in threat intel to scan for known indicators.

#### Supported:
- Simple list of IOCs (one per line)
- Matches across **all fields**
- Tracks which fields matched per record

```bash
--ioc my_iocs.txt --only-ioc-matches
```

### ✔️ Output Formats

ExecCheck supports:

- Terminal table view
- CSV
- JSON
- NDJSON (newline-delimited JSON for SIEMs)

```bash
--output-format [table|csv|json|ndjson]
```


## 🔄 Automate Your Workflow

You can integrate ExecCheck into your triage pipeline:

```bash
python3 -m execcheck \
  --db ./ExecPolicy \
  --config sample_config.yaml \
  --ioc ./ioc_hits.txt \
  --only-ioc-matches \
  --output-format ndjson \
  --output-path exec_results.ndjson
```

---

## 📁 Sample Files

- `sample_config.yaml` — scoring weights and settings
- `ExecPolicy` DB — must be extracted from disk image or mounted target

---

## 📦 Coming Soon

- HTML report viewer (optional)
- System UUID correlation
- Live agent/collection support (limited)

---

## 👤 Author & Credits

ExecCheck was developed to support real-world DFIR workflows with explainability and accuracy in mind.

Inspired by the work of:
- Patrick Wardle (macOS transparency pioneer)
- Countless incident responders doing forensic triage by hand

Contributions welcome.
