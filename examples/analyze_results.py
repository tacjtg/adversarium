#!/usr/bin/env python3
"""Load a previous run's results and regenerate visualizations.

Usage:
    python examples/analyze_results.py results/run_20240115_143022/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aces.attack.techniques import TechniqueRegistry
from aces.evolution.metrics import MetricsCollector
from aces.visualization.dashboard import Dashboard


def main() -> None:
    parser = argparse.ArgumentParser(description="ACES — Analyze Previous Run")
    parser.add_argument("results_dir", type=str, help="Path to results directory")
    args = parser.parse_args()

    TechniqueRegistry.reset()

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"Error: {results_dir} does not exist")
        sys.exit(1)

    # Load metrics
    metrics_path = results_dir / "evolution_log.json"
    if not metrics_path.exists():
        print(f"Error: {metrics_path} not found")
        sys.exit(1)

    metrics = MetricsCollector.from_json(str(metrics_path))

    from rich.console import Console
    console = Console()

    console.print(f"[bold]Loaded {len(metrics.history)} generations from {results_dir}[/bold]\n")

    # Print summary
    if metrics.history:
        last = metrics.history[-1]
        console.print(f"  Final attacker max effectiveness: {last.attacker_fitness_max:.2f}")
        console.print(f"  Final attacker mean stealth: {last.attacker_stealth_mean:.2f}")
        console.print(f"  Final defender max coverage: {last.defender_coverage_max:.2f}")
        console.print(f"  Unique kill chains: {last.unique_kill_chains}")
        console.print(f"  Detection coverage: {last.detection_coverage_ratio:.1%}")

    # Regenerate visualizations
    dashboard = Dashboard(metrics, [], [])
    dashboard.generate_all(str(results_dir))

    console.print(f"\n[bold green]Visualizations regenerated in {results_dir}[/bold green]")


if __name__ == "__main__":
    main()
