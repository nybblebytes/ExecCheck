"""Utility functions to translate numeric codes into human labels."""


def translate_malware_result(val: int) -> str:
    """Return a human readable label for a malware result code."""
    mapping = {
        0: "Not Malware",
        3: "Allow listed",
        4: "Weak Signature",
        8: "Bad Signature",
        10: "Revoked",
        11: "Known Malware",
        12: "Unnotarized Dev ID",
        13: "PUP",
    }
    return mapping.get(val, "Unknown")

def translate_policy_match(val: int) -> str:
    """Return a label for a policy match value."""
    mapping = {
        0: "No Match",
        1: "Allow",
        2: "Deny",
        3: "Override",
        4: "Quarantine",
        5: "Translocation",
        6: "Developer ID Match",
    }
    return mapping.get(val, "Unmapped")

def decode_flags(flag_value: int | None) -> list[str] | str:
    """Decode bitmask ``flag_value`` into a list of flag names."""
    if flag_value is None:
        return "missing"
    if flag_value == 0:
        return "no flags"
    flags = []
    if flag_value & 0x002:
        flags.append("Alert Shown")
    if flag_value & 0x004:
        flags.append("User Approved")
    if flag_value & 0x008:
        flags.append("User Override")
    if flag_value & 0x010:
        flags.append("Package")
    if flag_value & 0x040:
        flags.append("Developer Override")
    if flag_value & 0x80:
        flags.append("User Intent")
    if flag_value & 0x200:
        flags.append("Successful Evaluation")
    if flag_value & 0x400:
        flags.append("Blocked Override")
    return flags
