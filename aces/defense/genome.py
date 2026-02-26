"""Defender genome representation for evolutionary co-evolution."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aces.defense.detection import DEPLOY_COSTS, DetectionLogic, ResponseAction


class DetectionGene(BaseModel):
    """A single detection rule in a defender's configuration."""

    model_config = ConfigDict(frozen=False)

    technique_detected: str  # ATT&CK technique ID
    data_source: str
    detection_logic: DetectionLogic = DetectionLogic.SIGNATURE
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    false_positive_rate: float = Field(default=0.1, ge=0.0, le=1.0)
    response_action: ResponseAction = ResponseAction.ALERT_ONLY
    deploy_cost: float = 1.0


class DefenseGenome:
    """Unordered set of DetectionGenes, constrained by budget.

    Invariants:
        - len(genes) <= budget
        - No two genes detect the exact same technique with the same logic type
    """

    def __init__(self, genes: list[DetectionGene], budget: int = 15) -> None:
        self.genes = genes
        self.budget = budget
        # DEAP fitness placeholder
        self.fitness: object = None

    def covers_technique(self, technique_id: str) -> bool:
        """Check if any gene covers a technique."""
        return any(g.technique_detected == technique_id for g in self.genes)

    def get_detection_genes(self, technique_id: str) -> list[DetectionGene]:
        """Get all genes covering a technique."""
        return [g for g in self.genes if g.technique_detected == technique_id]

    def get_detection_probability(
        self, technique_id: str, stealth_modifier: float
    ) -> tuple[float, DetectionGene | None]:
        """Calculate detection probability for a technique.

        Returns (probability, best_matching_gene).
        """
        matching = self.get_detection_genes(technique_id)
        if not matching:
            return 0.0, None

        # Use the gene with highest effective detection probability
        best_gene = None
        best_prob = 0.0
        for gene in matching:
            prob = gene.confidence * (1.0 - stealth_modifier)
            if prob > best_prob:
                best_prob = prob
                best_gene = gene

        return best_prob, best_gene

    def total_false_positive_load(self) -> float:
        """Total false positive rate across all deployed rules."""
        return sum(g.false_positive_rate for g in self.genes)

    def total_deploy_cost(self) -> float:
        """Total deployment cost of all rules."""
        return sum(g.deploy_cost for g in self.genes)

    def __len__(self) -> int:
        return len(self.genes)

    def __repr__(self) -> str:
        techs = [g.technique_detected for g in self.genes]
        return f"DefenseGenome({len(self.genes)} rules: {techs})"
