from execcheck.translate import decode_flags, translate_malware_result, translate_policy_match


def test_unknown_malware_result_retains_raw_code():
    assert translate_malware_result(1) == "Unmapped (code=1)"


def test_unknown_policy_match_retains_raw_code():
    assert translate_policy_match(99) == "Unmapped (code=99)"


def test_unknown_flag_bits_remain_visible():
    decoded = decode_flags(0x2206)
    assert decoded["raw_value"] == 0x2206
    assert decoded["known_flags"] == [
        "Alert Shown",
        "User Approved",
        "Successful Evaluation",
    ]
    assert decoded["unknown_flag_mask"] == 0x2000
    assert decoded["unknown_flag_mask_hex"] == "0x2000"
