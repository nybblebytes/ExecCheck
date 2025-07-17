# ExecCheck Workflow

This guide summarizes how to run ExecCheck from acquiring the database to producing results.

## 1. Collect the ExecPolicy Database Offline
ExecCheck is designed for **offline analysis only**. Live systems lock the database so you must extract it first. Follow these steps taken from `README_ExecCheck.md`:

1. Boot the target Mac into Recovery Mode or use Target Disk Mode.
2. Mount the system volume externally (for example, `/Volumes/Macintosh HD`).
3. Copy the following files from the mounted volume:

   ```bash
   /var/db/SystemPolicyConfiguration/ExecPolicy
   /var/db/SystemPolicyConfiguration/ExecPolicy-shm
   /var/db/SystemPolicyConfiguration/ExecPolicy-wal
   ```

4. Provide the path to the copied `ExecPolicy` file with the `--db` argument when running ExecCheck.

## 2. Merge ExecPolicy Tables
The module [`combine.py`](execcheck/combine.py) merges records from several database tables into a single list. It correlates entries using `cdhash` or `file_identifier` and preserves provenance information. This gives you one set of rows ready for scoring and enrichment.

## 3. Enrich with VirusTotal (optional)
[`vt.py`](execcheck/vt.py) can query VirusTotal for each hash. If an API key is provided in your config and `--vt` is specified on the command line, hashes are submitted and enrichment fields like `vt_score` and `vt_malicious` are added.

## 4. Score Each Entry
[`scorer.py`](execcheck/scorer.py) calculates a risk score for every combined row. It checks properties such as unsigned binaries, blocked overrides and VirusTotal results. The `score_entry` function returns a numerical `risk_score` and an explanatory `score_trace`.

## 5. Generate Output
Run the tool with the CLI to produce results. Choose from table, CSV, JSON or NDJSON formats. Example:

```bash
python3 -m execcheck \
  --db ./ExecPolicy \
  --config sample_config.yaml \
  --vt \
  --output-format json \
  --output-path exec_results.json
```

ExecCheck will combine the tables, optionally enrich with VirusTotal, score each entry and write the output in your chosen format.

