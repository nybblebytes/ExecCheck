def translate_malware_result(val):
    mapping = {
        0: "No matching policy",
        1: "Signed by Apple",
        2: "App Store-signed",
        3: "Developer ID-signed",
        4: "Notarized",
        7: "Unsigned executable",
        9: "Unknown or no prior scan",
        10: "Revoked certificate",
        11: "Weak signature detected",
        12: "Legacy approval override"
    }
    return mapping.get(val, "Unknown")

def translate_policy_match(val):
    mapping = {
        0: "No Match",
        1: "Allow",
        2: "Deny",
        3: "Override",
        4: "Quarantine",
        5: "Translocation",
        6: "Developer ID Match",
        7: "Hardcoded Allow"
    }
    return mapping.get(val, "Unmapped")

def decode_flags(flag_value):
    if flag_value is None:
        return "missing"
    if flag_value == 0:
        return "no flags"
    flags = []
    if flag_value & 0x001:
        flags.append("fScanMigrated")
    if flag_value & 0x002:
        flags.append("Web Download (quarantine=2)")
    if flag_value & 0x004:
        flags.append("fScanUserApproved")
    if flag_value & 0x008:
        flags.append("fScanUserOverride")
    if flag_value & 0x010:
        flags.append("fScanPackage")
    if flag_value & 0x040:
        flags.append("fScanDeveloperOverride")
    if flag_value & 0x200:
        flags.append("fScanSuccessfulEvaluation")
    if flag_value & 0x400:
        flags.append("fScanBlockedOverride")
    return flags
