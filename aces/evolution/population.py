"""Population management and DEAP integration."""

from __future__ import annotations

import random as _random_module

from deap import base, creator, tools

from aces.attack.genome import AttackGenome
from aces.attack.operators import create_random_attacker, crossover_attack, mutate_attack
from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.defense.genome import DefenseGenome
from aces.defense.operators import create_random_defender, crossover_defense, mutate_defense


def _ensure_deap_types() -> None:
    """Register DEAP fitness and individual types (idempotent)."""
    if not hasattr(creator, "AttackerFitness"):
        creator.create("AttackerFitness", base.Fitness, weights=(1.0, 1.0))
    if not hasattr(creator, "DefenderFitness"):
        creator.create("DefenderFitness", base.Fitness, weights=(1.0, 1.0))


class PopulationManager:
    """Manages DEAP toolbox setup, population initialization, and hall of fame."""

    def __init__(self, config: Config, registry: TechniqueRegistry, rng: _random_module.Random) -> None:
        self.config = config
        self.registry = registry
        self.rng = rng
        _ensure_deap_types()

    def init_attacker_population(self, size: int) -> list[AttackGenome]:
        """Create initial attacker population."""
        pop = []
        for _ in range(size):
            ind = create_random_attacker(self.registry, self.config, self.rng)
            ind.fitness = creator.AttackerFitness()
            pop.append(ind)
        return pop

    def init_defender_population(self, size: int) -> list[DefenseGenome]:
        """Create initial defender population."""
        pop = []
        for _ in range(size):
            ind = create_random_defender(self.registry, self.config, self.rng)
            ind.fitness = creator.DefenderFitness()
            pop.append(ind)
        return pop

    def select_nsga2(self, population: list, k: int) -> list:
        """NSGA-II selection."""
        return tools.selNSGA2(population, k)

    def vary_attackers(
        self,
        population: list[AttackGenome],
        cxpb: float,
        mutpb: float,
    ) -> list[AttackGenome]:
        """Apply crossover and mutation to attacker population."""
        offspring = []
        # Clone population
        for ind in population:
            clone = AttackGenome(
                genes=[g.model_copy() for g in ind.genes],
                max_length=ind.max_length,
            )
            clone.fitness = creator.AttackerFitness()
            offspring.append(clone)

        # Crossover
        for i in range(1, len(offspring), 2):
            if self.rng.random() < cxpb:
                c1, c2 = crossover_attack(offspring[i - 1], offspring[i], self.rng)
                c1.fitness = creator.AttackerFitness()
                c2.fitness = creator.AttackerFitness()
                offspring[i - 1] = c1
                offspring[i] = c2

        # Mutation
        for i in range(len(offspring)):
            if self.rng.random() < mutpb:
                (mutated,) = mutate_attack(offspring[i], self.registry, self.config, self.rng)
                mutated.fitness = creator.AttackerFitness()
                offspring[i] = mutated

        return offspring

    def vary_defenders(
        self,
        population: list[DefenseGenome],
        cxpb: float,
        mutpb: float,
    ) -> list[DefenseGenome]:
        """Apply crossover and mutation to defender population."""
        offspring = []
        for ind in population:
            clone = DefenseGenome(
                genes=[g.model_copy() for g in ind.genes],
                budget=ind.budget,
            )
            clone.fitness = creator.DefenderFitness()
            offspring.append(clone)

        # Crossover
        for i in range(1, len(offspring), 2):
            if self.rng.random() < cxpb:
                c1, c2 = crossover_defense(offspring[i - 1], offspring[i], self.rng)
                c1.fitness = creator.DefenderFitness()
                c2.fitness = creator.DefenderFitness()
                offspring[i - 1] = c1
                offspring[i] = c2

        # Mutation
        for i in range(len(offspring)):
            if self.rng.random() < mutpb:
                (mutated,) = mutate_defense(offspring[i], self.registry, self.config, self.rng)
                mutated.fitness = creator.DefenderFitness()
                offspring[i] = mutated

        return offspring

    def inject_immigrants(
        self,
        population: list,
        pop_type: str,
        fraction: float = 0.1,
    ) -> list:
        """Replace worst individuals with random new ones."""
        n_immigrants = max(1, int(len(population) * fraction))

        # Sort by primary fitness (first objective), ascending
        valid_pop = [ind for ind in population if ind.fitness.valid]
        if valid_pop:
            valid_pop.sort(key=lambda x: x.fitness.values[0])
            # Remove worst
            remove_set = set(id(x) for x in valid_pop[:n_immigrants])
            population = [ind for ind in population if id(ind) not in remove_set]

        # Add immigrants
        for _ in range(n_immigrants):
            if pop_type == "attacker":
                ind = create_random_attacker(self.registry, self.config, self.rng)
                ind.fitness = creator.AttackerFitness()
            else:
                ind = create_random_defender(self.registry, self.config, self.rng)
                ind.fitness = creator.DefenderFitness()
            population.append(ind)

        return population
