import time
import requests

def query_vt(hash_list, api_key):
    headers = {"x-apikey": api_key}
    results = {}
    for h in hash_list:
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                results[h] = {
                    "vt_score": malicious,
                    "vt_malicious": malicious > 0
                }
            else:
                results[h] = {
                    "vt_score": None,
                    "vt_malicious": False
                }
        except Exception as e:
            results[h] = {
                "vt_score": None,
                "vt_malicious": False
            }
        time.sleep(15)  # Respect VT rate limit
    return results
