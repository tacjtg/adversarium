"""Phase 3 tests: attacker genome and operators."""

import random

from aces.attack.genome import AttackGenome, AttackGene, TargetSelector
from aces.attack.operators import create_random_attacker, crossover_attack, mutate_attack
from aces.attack.techniques import TechniqueRegistry
from aces.config import Config, Tactic


def setup_function():
    TechniqueRegistry.reset()


def test_random_attacker_validity():
    """Random attacker genome satisfies all invariants."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(50):
        genome = create_random_attacker(registry, config, rng)
        # Has at least 2 genes
        assert len(genome) >= 2
        # Within max length
        assert len(genome) <= config.max_attack_chain_length
        # First gene is initial access
        first_tech = registry.get(genome.genes[0].technique_id)
        assert first_tech.tactic == Tactic.INITIAL_ACCESS
        # All technique IDs valid
        for gene in genome.genes:
            assert gene.technique_id in registry


def test_attack_crossover_preserves_initial_access():
    """Crossover never produces child without initial access gene[0]."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(100):
        p1 = create_random_attacker(registry, config, rng)
        p2 = create_random_attacker(registry, config, rng)
        c1, c2 = crossover_attack(p1, p2, rng)

        # Both children start with initial access
        t1 = registry.get(c1.genes[0].technique_id)
        t2 = registry.get(c2.genes[0].technique_id)
        assert t1.tactic == Tactic.INITIAL_ACCESS, f"Child1 starts with {t1.tactic}"
        assert t2.tactic == Tactic.INITIAL_ACCESS, f"Child2 starts with {t2.tactic}"

        # Within max length
        assert len(c1) <= config.max_attack_chain_length
        assert len(c2) <= config.max_attack_chain_length

        # At least 2 genes
        assert len(c1) >= 2
        assert len(c2) >= 2


def test_attack_mutation_preserves_invariants():
    """All mutation types produce valid genomes."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    for _ in range(200):
        genome = create_random_attacker(registry, config, rng)
        (mutated,) = mutate_attack(genome, registry, config, rng)

        # First gene still initial access
        first_tech = registry.get(mutated.genes[0].technique_id)
        assert first_tech.tactic == Tactic.INITIAL_ACCESS

        # Within max length
        assert len(mutated) <= config.max_attack_chain_length

        # All IDs valid
        for gene in mutated.genes:
            assert gene.technique_id in registry

        # Stealth modifiers in range
        for gene in mutated.genes:
            assert 0.0 <= gene.stealth_modifier <= 1.0


def test_attack_chain_serialization():
    """to_attack_chain returns technique ID list."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    rng = random.Random(42)

    genome = create_random_attacker(registry, config, rng)
    chain = genome.to_attack_chain()
    assert len(chain) == len(genome)
    assert all(isinstance(t, str) for t in chain)
