"""Genetic operators for defender genomes."""

from __future__ import annotations

import random as _random_module

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.defense.detection import DEPLOY_COSTS, DetectionLogic, ResponseAction
from aces.defense.genome import DefenseGenome, DetectionGene

# Map detection logic -> typical FP rate range
_FP_RANGES: dict[DetectionLogic, tuple[float, float]] = {
    DetectionLogic.SIGNATURE: (0.01, 0.1),
    DetectionLogic.BEHAVIORAL: (0.05, 0.25),
    DetectionLogic.CORRELATION: (0.02, 0.15),
    DetectionLogic.ML_ANOMALY: (0.05, 0.2),
}


def create_random_defender(
    registry: TechniqueRegistry,
    config: Config,
    rng: _random_module.Random,
) -> DefenseGenome:
    """Generate a random valid defender genome.

    Selects 5-BUDGET random techniques and creates detection rules.
    """
    all_ids = registry.all_technique_ids()
    num_rules = rng.randint(5, config.defender_budget)
    selected_ids = rng.sample(all_ids, min(num_rules, len(all_ids)))

    genes: list[DetectionGene] = []
    seen: set[tuple[str, str]] = set()

    for tech_id in selected_ids:
        tech = registry.get(tech_id)
        logic = rng.choice(list(DetectionLogic))

        # Deduplicate
        key = (tech_id, logic.value)
        if key in seen:
            continue
        seen.add(key)

        fp_lo, fp_hi = _FP_RANGES[logic]
        data_source = rng.choice(tech.common_data_sources) if tech.common_data_sources else "Generic"

        gene = DetectionGene(
            technique_detected=tech_id,
            data_source=data_source,
            detection_logic=logic,
            confidence=round(rng.uniform(0.3, 0.9), 2),
            false_positive_rate=round(rng.uniform(fp_lo, fp_hi), 3),
            response_action=rng.choice(list(ResponseAction)),
            deploy_cost=DEPLOY_COSTS[logic],
        )
        genes.append(gene)

    return DefenseGenome(genes=genes, budget=config.defender_budget)


def crossover_defense(
    ind1: DefenseGenome,
    ind2: DefenseGenome,
    rng: _random_module.Random,
) -> tuple[DefenseGenome, DefenseGenome]:
    """Uniform crossover on detection gene sets.

    Pool all genes, assign each to child1 or child2 with 50% chance.
    Trim to budget and remove duplicates.
    """
    all_genes = ind1.genes + ind2.genes
    child1_genes: list[DetectionGene] = []
    child2_genes: list[DetectionGene] = []

    for gene in all_genes:
        if rng.random() < 0.5:
            child1_genes.append(gene.model_copy())
        else:
            child2_genes.append(gene.model_copy())

    # Remove duplicates and trim
    child1_genes = _deduplicate_and_trim(child1_genes, ind1.budget)
    child2_genes = _deduplicate_and_trim(child2_genes, ind2.budget)

    # Ensure at least 3 genes
    if len(child1_genes) < 3:
        child1_genes = ind1.genes[:3] if len(ind1.genes) >= 3 else [g.model_copy() for g in ind1.genes]
    if len(child2_genes) < 3:
        child2_genes = ind2.genes[:3] if len(ind2.genes) >= 3 else [g.model_copy() for g in ind2.genes]

    return (
        DefenseGenome(genes=child1_genes, budget=ind1.budget),
        DefenseGenome(genes=child2_genes, budget=ind2.budget),
    )


def mutate_defense(
    individual: DefenseGenome,
    registry: TechniqueRegistry,
    config: Config,
    rng: _random_module.Random,
) -> tuple[DefenseGenome]:
    """Apply one random mutation to the defender genome.

    Mutation types: ADD_RULE, REMOVE_RULE, CHANGE_LOGIC,
    TUNE_CONFIDENCE, CHANGE_RESPONSE, RETARGET.
    """
    mutation_type = rng.choice([
        "add_rule", "remove_rule", "change_logic",
        "tune_confidence", "change_response", "retarget",
    ])

    genes = individual.genes

    if mutation_type == "add_rule" and len(genes) < individual.budget:
        all_ids = registry.all_technique_ids()
        tech_id = rng.choice(all_ids)
        logic = rng.choice(list(DetectionLogic))

        # Check for duplicate
        existing = {(g.technique_detected, g.detection_logic.value) for g in genes}
        if (tech_id, logic.value) not in existing:
            tech = registry.get(tech_id)
            fp_lo, fp_hi = _FP_RANGES[logic]
            data_source = rng.choice(tech.common_data_sources) if tech.common_data_sources else "Generic"
            gene = DetectionGene(
                technique_detected=tech_id,
                data_source=data_source,
                detection_logic=logic,
                confidence=round(rng.uniform(0.3, 0.9), 2),
                false_positive_rate=round(rng.uniform(fp_lo, fp_hi), 3),
                response_action=rng.choice(list(ResponseAction)),
                deploy_cost=DEPLOY_COSTS[logic],
            )
            genes.append(gene)

    elif mutation_type == "remove_rule" and len(genes) > 3:
        idx = rng.randint(0, len(genes) - 1)
        genes.pop(idx)

    elif mutation_type == "change_logic" and genes:
        idx = rng.randint(0, len(genes) - 1)
        new_logic = rng.choice(list(DetectionLogic))
        # Check no duplicate
        existing = {(g.technique_detected, g.detection_logic.value) for i, g in enumerate(genes) if i != idx}
        if (genes[idx].technique_detected, new_logic.value) not in existing:
            genes[idx].detection_logic = new_logic
            genes[idx].deploy_cost = DEPLOY_COSTS[new_logic]
            fp_lo, fp_hi = _FP_RANGES[new_logic]
            genes[idx].false_positive_rate = round(rng.uniform(fp_lo, fp_hi), 3)

    elif mutation_type == "tune_confidence" and genes:
        idx = rng.randint(0, len(genes) - 1)
        delta = rng.uniform(-0.1, 0.1)
        new_val = max(0.1, min(1.0, genes[idx].confidence + delta))
        genes[idx].confidence = round(new_val, 2)

    elif mutation_type == "change_response" and genes:
        idx = rng.randint(0, len(genes) - 1)
        genes[idx].response_action = rng.choice(list(ResponseAction))

    elif mutation_type == "retarget" and genes:
        idx = rng.randint(0, len(genes) - 1)
        all_ids = registry.all_technique_ids()
        new_tech_id = rng.choice(all_ids)
        existing = {(g.technique_detected, g.detection_logic.value) for i, g in enumerate(genes) if i != idx}
        if (new_tech_id, genes[idx].detection_logic.value) not in existing:
            genes[idx].technique_detected = new_tech_id
            tech = registry.get(new_tech_id)
            if tech.common_data_sources:
                genes[idx].data_source = rng.choice(tech.common_data_sources)

    return (individual,)


def _deduplicate_and_trim(
    genes: list[DetectionGene], budget: int
) -> list[DetectionGene]:
    """Remove duplicate technique+logic pairs and trim to budget."""
    seen: set[tuple[str, str]] = set()
    unique: list[DetectionGene] = []
    for gene in genes:
        key = (gene.technique_detected, gene.detection_logic.value)
        if key not in seen:
            seen.add(key)
            unique.append(gene)

    # If over budget, drop lowest-confidence genes
    if len(unique) > budget:
        unique.sort(key=lambda g: g.confidence, reverse=True)
        unique = unique[:budget]

    return unique
