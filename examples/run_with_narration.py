#!/usr/bin/env python3
"""Full co-evolution run with LLM threat brief generation.

Requires ANTHROPIC_API_KEY environment variable.
Same as run_basic but adds LLM narration step at completion.

Usage:
    export ANTHROPIC_API_KEY=your_key_here
    python examples/run_with_narration.py
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.evolution.coevolution import CoevolutionEngine, save_results
from aces.narration.llm_narrator import LLMNarrator
from aces.visualization.dashboard import Dashboard


def main() -> None:
    parser = argparse.ArgumentParser(description="ACES — Co-Evolution with LLM Narration")
    parser.add_argument("--generations", type=int, default=None)
    parser.add_argument("--population", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--matchups", type=int, default=None)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"results/run_{timestamp}"

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=args.quiet)

    out_path = save_results(result, output_dir)

    # Visualizations
    dashboard = Dashboard(result.metrics, result.attacker_hof, result.defender_hof)
    dashboard.generate_all(str(out_path), network=engine.network)

    # LLM Narration
    from rich.console import Console
    console = Console()

    narrator = LLMNarrator()
    if narrator.available:
        console.print("\n[bold yellow]Generating LLM threat brief...[/bold yellow]")
        brief = narrator.generate_threat_brief(
            result.attacker_hof, result.defender_hof, result.metrics, engine.network
        )
        with open(out_path / "threat_brief.md", "w") as f:
            f.write(brief)
        console.print("[bold green]Threat brief generated![/bold green]")
    else:
        console.print(
            "[yellow]ANTHROPIC_API_KEY not set or anthropic not installed. "
            "Generating static brief.[/yellow]"
        )
        brief = narrator.generate_threat_brief(
            result.attacker_hof, result.defender_hof, result.metrics, engine.network
        )
        with open(out_path / "threat_brief.md", "w") as f:
            f.write(brief)

    # Generate unified dashboard
    dashboard.generate_unified_dashboard(
        output_path=str(out_path / "dashboard.html"),
        network=engine.network,
        threat_brief_md=brief,
        config_dict=config.model_dump(),
        elapsed_seconds=result.elapsed_seconds,
    )

    console.print(f"\n[bold green]Results saved to:[/bold green] {out_path}")
    console.print(f"  [bold]dashboard.html[/bold] — unified results dashboard")


if __name__ == "__main__":
    main()
