from datetime import datetime

def to_iso8601(ts):
    try:
        return datetime.utcfromtimestamp(ts).isoformat() + "Z"
    except:
        return "Invalid"
