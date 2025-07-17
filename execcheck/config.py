from pydantic import BaseModel, Field
import yaml
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
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return Config(**raw)
