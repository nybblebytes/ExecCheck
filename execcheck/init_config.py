"""Utility for generating a sample configuration file."""


def write_default_config() -> None:
    """Write ``sample_config.yaml`` to the current directory."""

    sample = """# Default ExecCheck config
# vt_api_key: "YOUR_API_KEY"
scoring:
  unsigned: 5
  missing_team_id: 3
  override_blocked: 7
  vt_malicious: 10
  custom_flag_mask: {}
whitelist:
  hashes: []
  team_ids: []
  paths: []
output:
  min_score: 0
  filters: {}
"""
    with open("sample_config.yaml", "w", encoding="utf-8") as file_handle:
        file_handle.write(sample)
    print("✅ sample_config.yaml written.")
