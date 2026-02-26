"""Attacker genome representation for evolutionary co-evolution."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from aces.network.assets import HostRole


class TargetSelector(str, Enum):
    """Strategy for selecting attack targets."""

    HIGHEST_CRITICALITY = "highest_criticality"
    LEAST_DEFENDED = "least_defended"
    MOST_CONNECTED = "most_connected"
    RANDOM_REACHABLE = "random_reachable"
    SPECIFIC_ROLE = "specific_role"


class AttackGene(BaseModel):
    """A single step in an attack chain."""

    model_config = ConfigDict(frozen=False)

    technique_id: str
    target_selector: TargetSelector = TargetSelector.RANDOM_REACHABLE
    target_role: HostRole | None = None
    fallback_technique: str | None = None
    stealth_modifier: float = Field(default=0.0, ge=0.0, le=1.0)


class AttackGenome:
    """Variable-length ordered sequence of AttackGenes representing a kill chain.

    Invariants:
        - genes[0] must be an initial access technique
        - len(genes) <= max_length
        - All technique IDs must exist in TechniqueRegistry
    """

    def __init__(self, genes: list[AttackGene], max_length: int = 12) -> None:
        self.genes = genes
        self.max_length = max_length
        # DEAP fitness placeholder — set by DEAP framework
        self.fitness: object = None

    @property
    def initial_access_gene(self) -> AttackGene:
        """The first gene (must be initial access)."""
        return self.genes[0]

    def to_attack_chain(self) -> list[str]:
        """Readable technique ID sequence."""
        return [g.technique_id for g in self.genes]

    def __len__(self) -> int:
        return len(self.genes)

    def __repr__(self) -> str:
        chain = " -> ".join(g.technique_id for g in self.genes)
        return f"AttackGenome({chain})"
