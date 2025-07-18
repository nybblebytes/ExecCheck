"""Configuration dataclasses and loader for ExecCheck."""

from pydantic import BaseModel
from typing import Optional

class ScoringWeights(BaseModel):
    unsigned: int
    missing_team_id: int
    override_blocked: int
    vt_malicious: int
    custom_flag_mask: dict[int, int]

class Whitelist(BaseModel):
    hashes: list[str]
    team_ids: list[str]
    paths: list[str]

class OutputConfig(BaseModel):
    min_score: int
    filters: dict

class Config(BaseModel):
    vt_api_key: Optional[str] = None
    scoring: ScoringWeights
    whitelist: Whitelist
    output: OutputConfig

def load_config(path: str) -> Config:
    """Load a YAML configuration file into a :class:`Config` object."""
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for loading configuration files. "
            "Install it with 'pip install pyyaml'."
        ) from exc

    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return Config(**raw)
