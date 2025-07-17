import sqlite3

def correlate_exec_data(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    scan_data = {}
    prov_data = {}

    try:
        cursor.execute("SELECT cdhash, file_identifier, bundle_id, flags, policy_match, top_policy_match, malware_result, volume_uuid, timestamp, revocation_check_time, mod_time FROM policy_scan_cache")
        for row in cursor.fetchall():
            record = dict(zip([col[0] for col in cursor.description], row))
            key_cdhash = (record.get("cdhash") or "").strip().lower()
            if key_cdhash:
                scan_data.setdefault(key_cdhash, []).append(record)
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("SELECT cdhash, file_identifier, bundle_id, flags, url, timestamp FROM provenance_tracking")
        for row in cursor.fetchall():
            record = dict(zip([col[0] for col in cursor.description], row))
            key_cdhash = (record.get("cdhash") or "").strip().lower()
            if key_cdhash:
                prov_data.setdefault(key_cdhash, []).append(record)
    except sqlite3.OperationalError:
        pass

    conn.close()
    return scan_data, prov_data
