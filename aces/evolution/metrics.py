"""Generation-level metrics and convergence tracking."""

from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path

from aces.attack.genome import AttackGenome
from aces.defense.genome import DefenseGenome
from aces.simulation.state import MatchResult


@dataclass
class GenerationMetrics:
    """Metrics for a single generation."""

    generation: int
    attacker_fitness_mean: float = 0.0
    attacker_fitness_max: float = 0.0
    attacker_fitness_min: float = 0.0
    attacker_fitness_std: float = 0.0
    attacker_stealth_mean: float = 0.0
    defender_coverage_mean: float = 0.0
    defender_coverage_max: float = 0.0
    defender_efficiency_mean: float = 0.0
    technique_frequencies: dict[str, float] = field(default_factory=dict)
    detection_coverage_ratio: float = 0.0
    attacker_diversity: float = 0.0
    defender_diversity: float = 0.0
    unique_kill_chains: int = 0


class MetricsCollector:
    """Collects and stores per-generation metrics."""

    def __init__(self) -> None:
        self.history: list[GenerationMetrics] = []

    def record_generation(
        self,
        gen: int,
        attackers: list[AttackGenome],
        defenders: list[DefenseGenome],
    ) -> GenerationMetrics:
        """Compute and store metrics for one generation."""
        m = GenerationMetrics(generation=gen)

        # Attacker fitness stats
        atk_primary = [
            ind.fitness.values[0]
            for ind in attackers
            if hasattr(ind.fitness, "values") and ind.fitness.valid
        ]
        atk_stealth = [
            ind.fitness.values[1]
            for ind in attackers
            if hasattr(ind.fitness, "values") and ind.fitness.valid
        ]

        if atk_primary:
            m.attacker_fitness_mean = statistics.mean(atk_primary)
            m.attacker_fitness_max = max(atk_primary)
            m.attacker_fitness_min = min(atk_primary)
            m.attacker_fitness_std = statistics.stdev(atk_primary) if len(atk_primary) > 1 else 0.0
        if atk_stealth:
            m.attacker_stealth_mean = statistics.mean(atk_stealth)

        # Defender fitness stats
        def_primary = [
            ind.fitness.values[0]
            for ind in defenders
            if hasattr(ind.fitness, "values") and ind.fitness.valid
        ]
        def_secondary = [
            ind.fitness.values[1]
            for ind in defenders
            if hasattr(ind.fitness, "values") and ind.fitness.valid
        ]

        if def_primary:
            m.defender_coverage_mean = statistics.mean(def_primary)
            m.defender_coverage_max = max(def_primary)
        if def_secondary:
            m.defender_efficiency_mean = statistics.mean(def_secondary)

        # Technique frequencies in attacker population
        tech_counts: dict[str, int] = {}
        total_genes = 0
        for atk in attackers:
            for gene in atk.genes:
                tech_counts[gene.technique_id] = tech_counts.get(gene.technique_id, 0) + 1
                total_genes += 1
        if total_genes > 0:
            m.technique_frequencies = {
                tid: count / total_genes for tid, count in tech_counts.items()
            }

        # Detection coverage ratio
        attacker_techniques = set(tech_counts.keys())
        if attacker_techniques:
            covered = sum(
                1 for tid in attacker_techniques
                if any(d.covers_technique(tid) for d in defenders)
            )
            m.detection_coverage_ratio = covered / len(attacker_techniques)

        # Unique kill chains
        chains = set()
        for atk in attackers:
            chain = tuple(g.technique_id for g in atk.genes)
            chains.add(chain)
        m.unique_kill_chains = len(chains)

        # Attacker diversity (simplified: unique chain ratio)
        m.attacker_diversity = len(chains) / max(len(attackers), 1)

        # Defender diversity
        def_configs = set()
        for d in defenders:
            config_key = tuple(sorted(g.technique_detected for g in d.genes))
            def_configs.add(config_key)
        m.defender_diversity = len(def_configs) / max(len(defenders), 1)

        self.history.append(m)
        return m

    def detect_stagnation(self, window: int = 20) -> bool:
        """True if max attacker fitness hasn't improved in `window` generations."""
        if len(self.history) < window:
            return False
        recent = self.history[-window:]
        max_vals = [m.attacker_fitness_max for m in recent]
        if not max_vals:
            return False
        # Check if improvement is negligible
        improvement = max(max_vals) - min(max_vals)
        return improvement < 0.5

    def to_json(self, path: str | Path) -> None:
        """Export metrics history to JSON."""
        data = [asdict(m) for m in self.history]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def from_json(cls, path: str | Path) -> MetricsCollector:
        """Load metrics from JSON."""
        collector = cls()
        with open(path) as f:
            data = json.load(f)
        for item in data:
            collector.history.append(GenerationMetrics(**item))
        return collector
