"""Utility for generating a sample configuration file."""


def write_default_config() -> None:
    """Write ``sample_config.yaml`` to the current directory."""

    sample = """# Default ExecCheck config
vt_api_key: "YOUR_API_KEY"
scoring:
  unsigned: 5
  missing_team_id: 3
  override_blocked: 7
  vt_malicious: 10
  custom_flag_mask:
    0x2000: 4
    0x800: 2
whitelist:
  hashes: []
  team_ids: []
  paths: []
output:
  min_score: 5
  filters:
    team_id_missing: true
    blocked: true
"""
    with open("sample_config.yaml", "w") as f:
        f.write(sample)
    print("✅ sample_config.yaml written.")
