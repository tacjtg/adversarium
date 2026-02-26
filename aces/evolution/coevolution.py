"""Main co-evolutionary loop orchestration."""

from __future__ import annotations

import json
import random as _random_module
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from aces.attack.genome import AttackGenome
from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.defense.genome import DefenseGenome
from aces.evolution.metrics import MetricsCollector
from aces.evolution.population import PopulationManager
from aces.network.graph import NetworkGraph
from aces.network.topology import TopologyGenerator
from aces.simulation.engine import SimulationEngine
from aces.simulation.scoring import compute_attacker_fitness, compute_defender_fitness
from aces.simulation.state import MatchResult

console = Console()


@dataclass
class EvolutionResult:
    """Complete results from a co-evolution run."""

    config: Config
    metrics: MetricsCollector
    attacker_hof: list[AttackGenome] = field(default_factory=list)
    defender_hof: list[DefenseGenome] = field(default_factory=list)
    final_attackers: list[AttackGenome] = field(default_factory=list)
    final_defenders: list[DefenseGenome] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class CoevolutionEngine:
    """Orchestrates the co-evolutionary simulation."""

    def __init__(self, config: Config, network: NetworkGraph | None = None) -> None:
        self.config = config
        self.rng = _random_module.Random(config.seed)
        self.registry = TechniqueRegistry()
        self.network = network or TopologyGenerator.corporate_medium()
        self.sim_engine = SimulationEngine(self.registry, self.rng)
        self.pop_manager = PopulationManager(config, self.registry, self.rng)
        self.metrics = MetricsCollector()
        self.attacker_hof: list[AttackGenome] = []
        self.defender_hof: list[DefenseGenome] = []

    def run(
        self,
        quiet: bool = False,
        on_generation: "callable | None" = None,
    ) -> EvolutionResult:
        """Execute the co-evolutionary loop.

        Args:
            quiet: Suppress terminal output.
            on_generation: Optional callback(gen, total, metrics_snapshot)
                           called after each generation for progress tracking.
        """
        start_time = time.time()

        attackers = self.pop_manager.init_attacker_population(self.config.population_size)
        defenders = self.pop_manager.init_defender_population(self.config.population_size)

        if not quiet:
            console.print(
                f"[bold green]ACES Co-Evolution[/bold green] — "
                f"Pop: {self.config.population_size} | "
                f"Gen: {self.config.num_generations} | "
                f"Seed: {self.config.seed}"
            )

        progress_ctx = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            disable=quiet,
        )

        with progress_ctx as progress:
            task = progress.add_task("Evolving...", total=self.config.num_generations)

            for gen in range(self.config.num_generations):
                # Evaluate attackers
                for attacker in attackers:
                    opponents = self.rng.sample(
                        defenders,
                        min(self.config.matchups_per_eval, len(defenders)),
                    )
                    # Mix in HOF defenders
                    if self.defender_hof:
                        n_hof = max(1, int(self.config.matchups_per_eval * self.config.hof_opponent_fraction))
                        hof_sample = self.rng.sample(
                            self.defender_hof,
                            min(n_hof, len(self.defender_hof)),
                        )
                        opponents = opponents[: self.config.matchups_per_eval - len(hof_sample)] + hof_sample

                    results = [
                        self.sim_engine.simulate(attacker, d, self.network)
                        for d in opponents
                    ]
                    attacker.fitness.values = compute_attacker_fitness(results, self.config)

                # Evaluate defenders
                for defender in defenders:
                    opponents = self.rng.sample(
                        attackers,
                        min(self.config.matchups_per_eval, len(attackers)),
                    )
                    if self.attacker_hof:
                        n_hof = max(1, int(self.config.matchups_per_eval * self.config.hof_opponent_fraction))
                        hof_sample = self.rng.sample(
                            self.attacker_hof,
                            min(n_hof, len(self.attacker_hof)),
                        )
                        opponents = opponents[: self.config.matchups_per_eval - len(hof_sample)] + hof_sample

                    results = [
                        self.sim_engine.simulate(a, defender, self.network)
                        for a in opponents
                    ]
                    fitness = compute_defender_fitness(results, self.config)
                    # Compute efficiency based on defender genome itself
                    fp_load = defender.total_false_positive_load()
                    rules_ratio = len(defender) / max(defender.budget, 1)
                    efficiency = (1.0 / (1.0 + fp_load)) * (1.0 - rules_ratio * 0.5)
                    defender.fitness.values = (fitness[0], efficiency)

                # Record metrics
                m = self.metrics.record_generation(gen, attackers, defenders)

                # Update hall of fame
                self._update_hof(attackers, defenders)

                # Log progress
                if not quiet and gen % max(1, self.config.num_generations // 20) == 0:
                    self._log_generation(gen, m)

                progress.update(task, advance=1)

                # Fire callback
                if on_generation is not None:
                    on_generation(gen, self.config.num_generations, m)

                # Select and reproduce
                selected_atk = self.pop_manager.select_nsga2(attackers, self.config.population_size)
                attackers = self.pop_manager.vary_attackers(
                    selected_atk, self.config.crossover_rate, self.config.mutation_rate
                )
                # Ensure fitness objects
                from deap import creator as _creator
                for ind in attackers:
                    if not hasattr(ind.fitness, "values") or not isinstance(ind.fitness, _creator.AttackerFitness):
                        ind.fitness = _creator.AttackerFitness()

                selected_def = self.pop_manager.select_nsga2(defenders, self.config.population_size)
                defenders = self.pop_manager.vary_defenders(
                    selected_def, self.config.crossover_rate, self.config.mutation_rate
                )
                for ind in defenders:
                    if not hasattr(ind.fitness, "values") or not isinstance(ind.fitness, _creator.DefenderFitness):
                        ind.fitness = _creator.DefenderFitness()

                # Elitism: inject HOF members
                self._inject_elites(attackers, self.attacker_hof, "attacker")
                self._inject_elites(defenders, self.defender_hof, "defender")

                # Diversity management
                if self.metrics.detect_stagnation(self.config.stagnation_window):
                    attackers = self.pop_manager.inject_immigrants(
                        attackers, "attacker", self.config.immigrant_fraction
                    )
                    defenders = self.pop_manager.inject_immigrants(
                        defenders, "defender", self.config.immigrant_fraction
                    )

        elapsed = time.time() - start_time

        if not quiet:
            console.print(f"\n[bold green]Evolution complete![/bold green] ({elapsed:.1f}s)")
            console.print(f"  Top attacker effectiveness: {self.metrics.history[-1].attacker_fitness_max:.2f}")
            console.print(f"  Top defender coverage: {self.metrics.history[-1].defender_coverage_max:.2f}")

        return EvolutionResult(
            config=self.config,
            metrics=self.metrics,
            attacker_hof=self.attacker_hof[:],
            defender_hof=self.defender_hof[:],
            final_attackers=attackers,
            final_defenders=defenders,
            elapsed_seconds=elapsed,
        )

    def _update_hof(self, attackers: list, defenders: list) -> None:
        """Update hall of fame with top individuals."""
        max_size = self.config.hall_of_fame_size

        # Attackers: sort by primary fitness descending
        valid_atk = [a for a in attackers if hasattr(a.fitness, "values") and a.fitness.valid]
        valid_atk.sort(key=lambda x: x.fitness.values[0], reverse=True)
        for ind in valid_atk[:max_size]:
            # Check if already in HOF (by chain)
            chain = tuple(g.technique_id for g in ind.genes)
            existing_chains = {tuple(g.technique_id for g in h.genes) for h in self.attacker_hof}
            if chain not in existing_chains:
                clone = AttackGenome(
                    genes=[g.model_copy() for g in ind.genes],
                    max_length=ind.max_length,
                )
                from deap import creator as _creator
                clone.fitness = _creator.AttackerFitness()
                clone.fitness.values = ind.fitness.values
                self.attacker_hof.append(clone)

        # Trim HOF
        self.attacker_hof.sort(key=lambda x: x.fitness.values[0] if x.fitness.valid else 0, reverse=True)
        self.attacker_hof = self.attacker_hof[:max_size]

        # Defenders
        valid_def = [d for d in defenders if hasattr(d.fitness, "values") and d.fitness.valid]
        valid_def.sort(key=lambda x: x.fitness.values[0], reverse=True)
        for ind in valid_def[:max_size]:
            techs = tuple(sorted(g.technique_detected for g in ind.genes))
            existing = {tuple(sorted(g.technique_detected for g in h.genes)) for h in self.defender_hof}
            if techs not in existing:
                clone = DefenseGenome(
                    genes=[g.model_copy() for g in ind.genes],
                    budget=ind.budget,
                )
                from deap import creator as _creator
                clone.fitness = _creator.DefenderFitness()
                clone.fitness.values = ind.fitness.values
                self.defender_hof.append(clone)

        self.defender_hof.sort(key=lambda x: x.fitness.values[0] if x.fitness.valid else 0, reverse=True)
        self.defender_hof = self.defender_hof[:max_size]

    def _inject_elites(self, population: list, hof: list, pop_type: str) -> None:
        """Ensure HOF members survive in population."""
        if not hof:
            return
        n_elites = min(2, len(hof))
        for i in range(n_elites):
            if i < len(population):
                if pop_type == "attacker":
                    clone = AttackGenome(
                        genes=[g.model_copy() for g in hof[i].genes],
                        max_length=hof[i].max_length,
                    )
                    from deap import creator as _creator
                    clone.fitness = _creator.AttackerFitness()
                    clone.fitness.values = hof[i].fitness.values
                else:
                    clone = DefenseGenome(
                        genes=[g.model_copy() for g in hof[i].genes],
                        budget=hof[i].budget,
                    )
                    from deap import creator as _creator
                    clone.fitness = _creator.DefenderFitness()
                    clone.fitness.values = hof[i].fitness.values
                population[i] = clone

    def _log_generation(self, gen: int, m) -> None:
        """Log generation summary."""
        console.print(
            f"  Gen {gen:04d} | "
            f"[red]ATK[/red] eff={m.attacker_fitness_mean:.1f} stl={m.attacker_stealth_mean:.2f} | "
            f"[blue]DEF[/blue] cov={m.defender_coverage_mean:.1f} eff={m.defender_efficiency_mean:.2f} | "
            f"chains={m.unique_kill_chains}"
        )


def save_results(result: EvolutionResult, output_dir: str | Path) -> Path:
    """Save all run results to the output directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Config
    with open(out / "config.json", "w") as f:
        json.dump(result.config.model_dump(), f, indent=2)

    # Metrics
    result.metrics.to_json(out / "evolution_log.json")

    # Hall of fame — attackers
    atk_hof_data = []
    for atk in result.attacker_hof:
        atk_hof_data.append({
            "kill_chain": atk.to_attack_chain(),
            "fitness": list(atk.fitness.values) if atk.fitness.valid else [0, 0],
            "genes": [
                {
                    "technique_id": g.technique_id,
                    "target_selector": g.target_selector.value,
                    "stealth_modifier": g.stealth_modifier,
                }
                for g in atk.genes
            ],
        })
    with open(out / "hall_of_fame_attackers.json", "w") as f:
        json.dump(atk_hof_data, f, indent=2)

    # Hall of fame — defenders
    def_hof_data = []
    for d in result.defender_hof:
        def_hof_data.append({
            "rules": [
                {
                    "technique_detected": g.technique_detected,
                    "detection_logic": g.detection_logic.value,
                    "confidence": g.confidence,
                    "response_action": g.response_action.value,
                    "false_positive_rate": g.false_positive_rate,
                }
                for g in d.genes
            ],
            "fitness": list(d.fitness.values) if d.fitness.valid else [0, 0],
        })
    with open(out / "hall_of_fame_defenders.json", "w") as f:
        json.dump(def_hof_data, f, indent=2)

    return out
