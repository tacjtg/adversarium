#!/usr/bin/env python3
"""Minimal co-evolution run with default parameters.

Outputs results to results/run_[timestamp]/.
Prints generation summaries to terminal via rich.
Generates all visualizations at completion.
No LLM narration.

Usage:
    python examples/run_basic.py
    python examples/run_basic.py --generations 50 --population 20 --seed 42
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.evolution.coevolution import CoevolutionEngine, save_results
from aces.visualization.dashboard import Dashboard


def main() -> None:
    parser = argparse.ArgumentParser(description="ACES — Basic Co-Evolution Run")
    parser.add_argument("--generations", type=int, default=None, help="Number of generations")
    parser.add_argument("--population", type=int, default=None, help="Population size")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--matchups", type=int, default=None, help="Matchups per evaluation")
    parser.add_argument("--output", type=str, default=None, help="Output directory")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    # Reset singleton for clean start
    TechniqueRegistry.reset()

    config = Config.from_defaults()
    if args.generations is not None:
        config.num_generations = args.generations
    if args.population is not None:
        config.population_size = args.population
    if args.seed is not None:
        config.seed = args.seed
    if args.matchups is not None:
        config.matchups_per_eval = args.matchups

    # Output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"results/run_{timestamp}"

    # Run co-evolution
    engine = CoevolutionEngine(config)
    result = engine.run(quiet=args.quiet)

    # Save results
    out_path = save_results(result, output_dir)

    # Generate threat brief (static — no LLM)
    from aces.narration.llm_narrator import LLMNarrator
    narrator = LLMNarrator()
    brief = narrator.generate_threat_brief(
        result.attacker_hof, result.defender_hof, result.metrics, engine.network
    )
    with open(out_path / "threat_brief.md", "w") as f:
        f.write(brief)

    # Generate individual chart files
    dashboard = Dashboard(result.metrics, result.attacker_hof, result.defender_hof)
    dashboard.generate_all(str(out_path), network=engine.network)

    # Generate unified dashboard
    dashboard.generate_unified_dashboard(
        output_path=str(out_path / "dashboard.html"),
        network=engine.network,
        threat_brief_md=brief,
        config_dict=config.model_dump(),
        elapsed_seconds=result.elapsed_seconds,
    )

    from rich.console import Console
    console = Console()
    console.print(f"\n[bold green]Results saved to:[/bold green] {out_path}")
    console.print(f"  [bold]dashboard.html[/bold] — unified results dashboard")
    console.print(f"  evolution_log.json — {len(result.metrics.history)} generations")
    console.print(f"  hall_of_fame_attackers.json — {len(result.attacker_hof)} top attackers")
    console.print(f"  hall_of_fame_defenders.json — {len(result.defender_hof)} top defenders")
    console.print(f"  6 individual chart files (HTML)")
    console.print(f"  threat_brief.md")


if __name__ == "__main__":
    main()
