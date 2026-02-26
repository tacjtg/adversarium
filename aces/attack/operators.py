"""Genetic operators for attacker genomes."""

from __future__ import annotations

import random as _random_module

from aces.attack.genome import AttackGene, AttackGenome, TargetSelector
from aces.attack.techniques import TechniqueRegistry
from aces.config import Config, Tactic
from aces.network.assets import HostRole


def create_random_attacker(
    registry: TechniqueRegistry,
    config: Config,
    rng: _random_module.Random,
) -> AttackGenome:
    """Generate a random valid attacker genome.

    1. Select random initial access technique for genes[0]
    2. Select 2-8 additional techniques following approximate tactic ordering
    3. Assign random target_selector and stealth_modifier to each gene
    """
    ia_techniques = registry.get_initial_access()
    ia = rng.choice(ia_techniques)

    genes: list[AttackGene] = [
        AttackGene(
            technique_id=ia.id,
            target_selector=rng.choice(list(TargetSelector)),
            target_role=rng.choice(list(HostRole)) if rng.random() < 0.3 else None,
            stealth_modifier=round(rng.uniform(0.0, 0.5), 2),
        )
    ]

    # Build a chain of 2-8 more techniques, loosely ordered by tactic
    chain_length = rng.randint(2, min(8, config.max_attack_chain_length - 1))
    post_ia_tactics = [
        Tactic.EXECUTION,
        Tactic.PERSISTENCE,
        Tactic.PRIVILEGE_ESCALATION,
        Tactic.DEFENSE_EVASION,
        Tactic.CREDENTIAL_ACCESS,
        Tactic.DISCOVERY,
        Tactic.LATERAL_MOVEMENT,
        Tactic.COLLECTION,
        Tactic.EXFILTRATION,
    ]

    for _ in range(chain_length):
        tactic = rng.choice(post_ia_tactics)
        candidates = registry.get_by_tactic(tactic)
        if not candidates:
            continue
        tech = rng.choice(candidates)
        genes.append(AttackGene(
            technique_id=tech.id,
            target_selector=rng.choice(list(TargetSelector)),
            target_role=rng.choice(list(HostRole)) if rng.random() < 0.3 else None,
            stealth_modifier=round(rng.uniform(0.0, 0.5), 2),
        ))

    return AttackGenome(genes=genes, max_length=config.max_attack_chain_length)


def crossover_attack(
    ind1: AttackGenome,
    ind2: AttackGenome,
    rng: _random_module.Random,
) -> tuple[AttackGenome, AttackGenome]:
    """Single-point crossover on gene sequences.

    Preserves initial access gene at position 0.
    """
    # Crossover points (at least 1 to preserve initial access)
    pt1 = rng.randint(1, max(1, len(ind1.genes) - 1))
    pt2 = rng.randint(1, max(1, len(ind2.genes) - 1))

    # Swap tails
    new_genes1 = ind1.genes[:pt1] + ind2.genes[pt2:]
    new_genes2 = ind2.genes[:pt2] + ind1.genes[pt1:]

    # Truncate to max length
    new_genes1 = new_genes1[: ind1.max_length]
    new_genes2 = new_genes2[: ind2.max_length]

    # Ensure at least 2 genes
    if len(new_genes1) < 2:
        new_genes1 = ind1.genes[:2] if len(ind1.genes) >= 2 else ind1.genes[:]
    if len(new_genes2) < 2:
        new_genes2 = ind2.genes[:2] if len(ind2.genes) >= 2 else ind2.genes[:]

    child1 = AttackGenome(genes=new_genes1, max_length=ind1.max_length)
    child2 = AttackGenome(genes=new_genes2, max_length=ind2.max_length)

    # Repair: ensure genes[0] is initial access
    _repair_initial_access(child1, ind1)
    _repair_initial_access(child2, ind2)

    return child1, child2


def mutate_attack(
    individual: AttackGenome,
    registry: TechniqueRegistry,
    config: Config,
    rng: _random_module.Random,
) -> tuple[AttackGenome]:
    """Apply one random mutation to the attacker genome.

    Mutation types: ADD_GENE, REMOVE_GENE, SWAP_GENES,
    MODIFY_TECHNIQUE, MODIFY_TARGETING, MODIFY_STEALTH.
    """
    mutation_type = rng.choice([
        "add_gene", "remove_gene", "swap_genes",
        "modify_technique", "modify_targeting", "modify_stealth",
    ])

    genes = individual.genes

    if mutation_type == "add_gene" and len(genes) < individual.max_length:
        tactic = rng.choice(list(Tactic))
        candidates = registry.get_by_tactic(tactic)
        if candidates:
            tech = rng.choice(candidates)
            new_gene = AttackGene(
                technique_id=tech.id,
                target_selector=rng.choice(list(TargetSelector)),
                target_role=rng.choice(list(HostRole)) if rng.random() < 0.3 else None,
                stealth_modifier=round(rng.uniform(0.0, 0.5), 2),
            )
            pos = rng.randint(1, len(genes))  # Never at position 0
            genes.insert(pos, new_gene)

    elif mutation_type == "remove_gene" and len(genes) > 2:
        idx = rng.randint(1, len(genes) - 1)  # Never remove position 0
        genes.pop(idx)

    elif mutation_type == "swap_genes" and len(genes) > 2:
        i = rng.randint(1, len(genes) - 1)
        j = rng.randint(1, len(genes) - 1)
        genes[i], genes[j] = genes[j], genes[i]

    elif mutation_type == "modify_technique":
        idx = rng.randint(1, len(genes) - 1) if len(genes) > 1 else 0
        if idx == 0:
            # Only replace with another initial access technique
            ia_techniques = registry.get_initial_access()
            tech = rng.choice(ia_techniques)
        else:
            old_tech = registry.get(genes[idx].technique_id)
            candidates = registry.get_by_tactic(old_tech.tactic)
            tech = rng.choice(candidates)
        genes[idx].technique_id = tech.id

    elif mutation_type == "modify_targeting":
        idx = rng.randint(0, len(genes) - 1)
        genes[idx].target_selector = rng.choice(list(TargetSelector))
        if genes[idx].target_selector == TargetSelector.SPECIFIC_ROLE:
            genes[idx].target_role = rng.choice(list(HostRole))

    elif mutation_type == "modify_stealth":
        idx = rng.randint(0, len(genes) - 1)
        delta = rng.uniform(-0.1, 0.1)
        new_val = max(0.0, min(1.0, genes[idx].stealth_modifier + delta))
        genes[idx].stealth_modifier = round(new_val, 2)

    return (individual,)


def _repair_initial_access(genome: AttackGenome, template: AttackGenome) -> None:
    """Ensure genes[0] is an initial access technique."""
    registry = TechniqueRegistry()
    if not genome.genes:
        genome.genes = [template.initial_access_gene.model_copy()]
        return
    first_tech = registry.get(genome.genes[0].technique_id)
    if first_tech.tactic != Tactic.INITIAL_ACCESS:
        genome.genes[0] = template.initial_access_gene.model_copy()
