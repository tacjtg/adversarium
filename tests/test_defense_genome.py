"""Phase 3 tests: defender genome and operators."""

import random

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.defense.genome import DefenseGenome, DetectionGene
from aces.defense.operators import create_random_defender, crossover_defense, mutate_defense


def setup_function():
    TechniqueRegistry.reset()


def test_random_defender_within_budget():
    """Random defender genome does not exceed budget."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(50):
        genome = create_random_defender(registry, config, rng)
        assert len(genome) <= config.defender_budget
        assert len(genome) >= 3  # At least a few rules


def test_random_defender_no_duplicates():
    """Random defender has no duplicate technique+logic pairs."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(50):
        genome = create_random_defender(registry, config, rng)
        seen = set()
        for gene in genome.genes:
            key = (gene.technique_detected, gene.detection_logic.value)
            assert key not in seen, f"Duplicate detection: {key}"
            seen.add(key)


def test_defense_crossover_budget_enforcement():
    """Crossover trims children to budget."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(100):
        p1 = create_random_defender(registry, config, rng)
        p2 = create_random_defender(registry, config, rng)
        c1, c2 = crossover_defense(p1, p2, rng)

        assert len(c1) <= config.defender_budget
        assert len(c2) <= config.defender_budget
        assert len(c1) >= 1
        assert len(c2) >= 1


def test_defense_mutation_no_duplicates():
    """Mutation never creates duplicate technique+logic pairs."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(200):
        genome = create_random_defender(registry, config, rng)
        (mutated,) = mutate_defense(genome, registry, config, rng)

        seen = set()
        for gene in mutated.genes:
            key = (gene.technique_detected, gene.detection_logic.value)
            assert key not in seen, f"Duplicate after mutation: {key}"
            seen.add(key)

        assert len(mutated) <= config.defender_budget


def test_defense_detection_probability():
    """Detection probability calculation works correctly."""
    from aces.defense.detection import DetectionLogic, ResponseAction

    gene = DetectionGene(
        technique_detected="T1566.001",
        data_source="Email Gateway",
        detection_logic=DetectionLogic.SIGNATURE,
        confidence=0.8,
        false_positive_rate=0.05,
        response_action=ResponseAction.ALERT_ONLY,
    )
    genome = DefenseGenome(genes=[gene], budget=15)

    # With no stealth modifier, prob = confidence * 1.0
    prob, matched = genome.get_detection_probability("T1566.001", 0.0)
    assert abs(prob - 0.8) < 0.001
    assert matched is gene

    # With stealth modifier 0.5, prob = 0.8 * 0.5 = 0.4
    prob, matched = genome.get_detection_probability("T1566.001", 0.5)
    assert abs(prob - 0.4) < 0.001

    # Technique not covered
    prob, matched = genome.get_detection_probability("T1190", 0.0)
    assert prob == 0.0
    assert matched is None


def test_defense_false_positive_load():
    """Total FP load sums across all genes."""
    from aces.defense.detection import DetectionLogic, ResponseAction

    genes = [
        DetectionGene(
            technique_detected="T1566.001",
            data_source="Email Gateway",
            detection_logic=DetectionLogic.SIGNATURE,
            confidence=0.8,
            false_positive_rate=0.1,
            response_action=ResponseAction.ALERT_ONLY,
        ),
        DetectionGene(
            technique_detected="T1190",
            data_source="Network Traffic",
            detection_logic=DetectionLogic.BEHAVIORAL,
            confidence=0.6,
            false_positive_rate=0.2,
            response_action=ResponseAction.ISOLATE_HOST,
        ),
    ]
    genome = DefenseGenome(genes=genes, budget=15)
    assert abs(genome.total_false_positive_load() - 0.3) < 0.001
