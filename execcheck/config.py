"""Validated configuration models and YAML loading for ExecCheck."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ScoringWeights(BaseModel):
    unsigned: int = 5
    missing_team_id: int = 3
    override_blocked: int = 7
    vt_malicious: int = 10
    # Apple flag meanings outside translate.py's documented mapping are not
    # inferred. Organization/research-specific scoring is explicitly opt-in.
    custom_flag_mask: dict[int | str, int] = Field(default_factory=dict)


class Whitelist(BaseModel):
    hashes: list[str] = Field(default_factory=list)
    team_ids: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)


class OutputConfig(BaseModel):
    min_score: int = 0
    filters: dict[str, Any] = Field(default_factory=dict)


class Config(BaseModel):
    vt_api_key: Optional[str] = None
    scoring: ScoringWeights = Field(default_factory=ScoringWeights)
    whitelist: Whitelist = Field(default_factory=Whitelist)
    output: OutputConfig = Field(default_factory=OutputConfig)
    color_thresholds: dict[str, int] = Field(
        default_factory=lambda: {"yellow": 5, "red": 10}
    )


def config_dict(config: Config) -> dict[str, Any]:
    """Support both Pydantic 1 and 2 without warnings in callers."""
    if hasattr(config, "model_dump"):
        return config.model_dump()
    return config.dict()


def load_config(path: str) -> Config:
    """Load a YAML configuration file into a :class:`Config` object."""
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for loading configuration files. "
            "Install it with 'pip install pyyaml'."
        ) from exc

    with open(path, "r", encoding="utf-8") as file_handle:
        raw = yaml.safe_load(file_handle) or {}
    return Config(**raw)
