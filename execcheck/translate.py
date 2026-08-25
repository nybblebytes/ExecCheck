"""Lossless translations of documented ExecPolicy numeric values."""

from __future__ import annotations


MALWARE_RESULTS = {
    0: "Not Malware",
    3: "Allow listed",
    4: "Weak Signature",
    8: "Bad Signature",
    10: "Revoked",
    11: "Known Malware",
    12: "Unnotarized Dev ID",
    13: "PUP",
}

POLICY_MATCHES = {
    0: "No Match",
    1: "Allow",
    2: "Deny",
    3: "Override",
    4: "Quarantine",
    5: "Translocation",
    6: "Developer ID Match",
}

KNOWN_FLAGS = {
    0x002: "Alert Shown",
    0x004: "User Approved",
    0x008: "User Override",
    0x010: "Package",
    0x040: "Developer Override",
    0x080: "User Intent",
    0x200: "Successful Evaluation",
    0x400: "Blocked Override",
}


def translate_malware_result(val: int | None) -> str:
    """Translate known values and retain every unknown raw numeric code."""
    if val is None:
        return "Unknown (not observed)"
    return MALWARE_RESULTS.get(val, f"Unmapped (code={val})")


def translate_policy_match(val: int | None) -> str:
    """Translate known values and retain every unknown raw numeric code."""
    if val is None:
        return "Unknown (not observed)"
    return POLICY_MATCHES.get(val, f"Unmapped (code={val})")


def decode_flags(flag_value: int | None) -> dict:
    """Return known meanings plus raw value and all unmapped bits."""
    if flag_value is None:
        return {
            "raw_value": None,
            "raw_hex": None,
            "known_flags": [],
            "unknown_flag_mask": None,
            "unknown_flag_mask_hex": None,
            "state": "unknown",
        }
    known_flags = [label for mask, label in KNOWN_FLAGS.items() if flag_value & mask]
    known_mask = 0
    for mask in KNOWN_FLAGS:
        known_mask |= mask
    unknown_mask = flag_value & ~known_mask
    return {
        "raw_value": flag_value,
        "raw_hex": hex(flag_value),
        "known_flags": known_flags,
        "unknown_flag_mask": unknown_mask,
        "unknown_flag_mask_hex": hex(unknown_mask),
        "state": "observed",
    }
