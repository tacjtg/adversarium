"""Global configuration and constants for ACES."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class Tactic(str, Enum):
    """ATT&CK tactics in kill chain order."""

    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


TACTIC_ORDER: list[Tactic] = list(Tactic)


class ScoringWeights(BaseModel):
    """Weights used in fitness scoring."""

    model_config = ConfigDict(frozen=True)

    # Attacker effectiveness weights
    host_criticality_multiplier: float = 10.0
    credential_value: float = 3.0
    exfiltration_bonus: float = 50.0
    kill_chain_length_value: float = 2.0
    detection_penalty: float = 5.0

    # Defender coverage weights
    detection_value: float = 10.0  # per technique detected (scaled by severity)
    prevention_value: float = 10.0  # per attack prevented by response
    no_exfil_bonus: float = 30.0
    false_positive_penalty: float = 5.0
    complexity_cost: float = 1.0


class Config(BaseModel):
    """Central configuration for an ACES run."""

    model_config = ConfigDict(frozen=False)

    # Population parameters
    population_size: int = 80
    num_generations: int = 300
    tournament_size: int = 5
    crossover_rate: float = 0.7
    mutation_rate: float = 0.2

    # Genome constraints
    max_attack_chain_length: int = 12
    defender_budget: int = 15

    # Network
    network_size: int = 25

    # Evolution
    hall_of_fame_size: int = 10
    matchups_per_eval: int = 5
    stagnation_window: int = 20
    immigrant_fraction: float = 0.1
    hof_opponent_fraction: float = 0.2

    # Scoring
    scoring: ScoringWeights = ScoringWeights()

    # Output
    output_dir: str = "results"

    # Reproducibility
    seed: int = 42

    @classmethod
    def from_defaults(cls) -> Config:
        """Create config with defaults, overridden by ACES_ env vars."""
        overrides: dict = {}
        for field_name in cls.model_fields:
            env_key = f"ACES_{field_name.upper()}"
            val = os.environ.get(env_key)
            if val is not None:
                field_info = cls.model_fields[field_name]
                if field_info.annotation in (int,):
                    overrides[field_name] = int(val)
                elif field_info.annotation in (float,):
                    overrides[field_name] = float(val)
                else:
                    overrides[field_name] = val
        return cls(**overrides)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        """Load config from a YAML file (optional dependency)."""
        import yaml  # type: ignore[import-untyped]

        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
