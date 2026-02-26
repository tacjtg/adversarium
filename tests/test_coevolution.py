"""Phase 5 tests: co-evolution loop."""

import json

from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.evolution.coevolution import CoevolutionEngine, save_results
from aces.evolution.metrics import MetricsCollector


def setup_function():
    TechniqueRegistry.reset()


def test_coevolution_runs_without_error():
    """A minimal run (10 generations, pop 10) completes without exceptions."""
    config = Config.from_defaults()
    config.population_size = 10
    config.num_generations = 10
    config.matchups_per_eval = 3
    config.seed = 42

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=True)

    assert len(result.metrics.history) == 10
    assert result.elapsed_seconds > 0


def test_fitness_improves_over_generations():
    """Over 30 generations, max attacker fitness should increase."""
    config = Config.from_defaults()
    config.population_size = 15
    config.num_generations = 30
    config.matchups_per_eval = 3
    config.seed = 42

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=True)

    history = result.metrics.history
    early_max = max(m.attacker_fitness_max for m in history[:10])
    late_max = max(m.attacker_fitness_max for m in history[-10:])

    # Late generations should be at least as good as early
    assert late_max >= early_max * 0.8, (
        f"Late max {late_max:.2f} did not improve over early {early_max:.2f}"
    )


def test_hall_of_fame_populated():
    """After evolution, HOF contains individuals."""
    config = Config.from_defaults()
    config.population_size = 10
    config.num_generations = 15
    config.matchups_per_eval = 3
    config.seed = 42

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=True)

    assert len(result.attacker_hof) > 0
    assert len(result.defender_hof) > 0


def test_stagnation_detection():
    """MetricsCollector correctly identifies fitness plateau."""
    collector = MetricsCollector()

    # Add 25 generations with constant fitness
    from aces.evolution.metrics import GenerationMetrics

    for i in range(25):
        m = GenerationMetrics(
            generation=i,
            attacker_fitness_max=10.0,
            attacker_fitness_mean=8.0,
        )
        collector.history.append(m)

    assert collector.detect_stagnation(window=20)

    # Add improving generations
    for i in range(25, 50):
        m = GenerationMetrics(
            generation=i,
            attacker_fitness_max=10.0 + i,
            attacker_fitness_mean=8.0 + i,
        )
        collector.history.append(m)

    assert not collector.detect_stagnation(window=20)


def test_metrics_serialization(tmp_path):
    """Metrics export to JSON and reload correctly."""
    config = Config.from_defaults()
    config.population_size = 10
    config.num_generations = 5
    config.matchups_per_eval = 2
    config.seed = 42

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=True)

    json_path = tmp_path / "metrics.json"
    result.metrics.to_json(str(json_path))

    loaded = MetricsCollector.from_json(str(json_path))
    assert len(loaded.history) == len(result.metrics.history)
    assert loaded.history[0].generation == 0


def test_save_results(tmp_path):
    """save_results creates all expected output files."""
    config = Config.from_defaults()
    config.population_size = 10
    config.num_generations = 5
    config.matchups_per_eval = 2
    config.seed = 42

    engine = CoevolutionEngine(config)
    result = engine.run(quiet=True)

    out_dir = tmp_path / "test_run"
    save_results(result, out_dir)

    assert (out_dir / "config.json").exists()
    assert (out_dir / "evolution_log.json").exists()
    assert (out_dir / "hall_of_fame_attackers.json").exists()
    assert (out_dir / "hall_of_fame_defenders.json").exists()

    # Verify JSON is valid
    with open(out_dir / "config.json") as f:
        data = json.load(f)
    assert data["population_size"] == 10
