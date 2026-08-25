"""Simple VirusTotal lookups for hash enrichment."""

import time
import requests

def query_vt(hash_list: list[str], api_key: str) -> dict:
    """Return VirusTotal results for each hash in ``hash_list``."""

    headers = {"x-apikey": api_key}
    results = {}
    for h in hash_list:
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
                malicious = stats.get("malicious") if isinstance(stats, dict) else None
                results[h] = {
                    "vt_score": malicious,
                    "vt_malicious": malicious > 0 if isinstance(malicious, int) else None,
                    "vt_analysis_stats": stats,
                    "vt_evidence_state": "observed" if isinstance(malicious, int) else "unknown",
                }
            else:
                results[h] = {
                    "vt_score": None,
                    "vt_malicious": None,
                    "vt_analysis_stats": None,
                    "vt_evidence_state": "unknown",
                    "vt_error": f"HTTP status {response.status_code}",
                }
        except requests.RequestException as error:
            results[h] = {
                "vt_score": None,
                "vt_malicious": None,
                "vt_analysis_stats": None,
                "vt_evidence_state": "unknown",
                "vt_error": f"{type(error).__name__}: {error}",
            }
        time.sleep(15)  # Respect VT rate limit
    return results
