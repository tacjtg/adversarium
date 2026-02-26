"""Fitness scoring functions for attacker and defender populations."""

from __future__ import annotations

from aces.config import Config
from aces.simulation.state import EventOutcome, MatchResult


def compute_attacker_fitness(
    results: list[MatchResult], config: Config
) -> tuple[float, float]:
    """Compute multi-objective attacker fitness: (effectiveness, stealth).

    effectiveness = mean across matchups of:
        sum(host.criticality for host in compromised_hosts) * host_criticality_multiplier
        + credentials_obtained * credential_value
        + (exfiltration_bonus if data_exfiltrated else 0)
        + kill_chain_length * kill_chain_length_value

    stealth = mean across matchups of:
        1.0 - (techniques_detected / max(techniques_attempted, 1))
    """
    if not results:
        return (0.0, 0.0)

    w = config.scoring
    total_effectiveness = 0.0
    total_stealth = 0.0

    for r in results:
        effectiveness = (
            r.max_criticality_reached * r.hosts_compromised * w.host_criticality_multiplier
            + r.credentials_obtained * w.credential_value
            + (w.exfiltration_bonus if r.data_exfiltrated else 0.0)
            + r.kill_chain_length * w.kill_chain_length_value
        )
        total_effectiveness += effectiveness

        attempted = max(r.techniques_attempted, 1)
        stealth = 1.0 - (r.techniques_detected / attempted)
        total_stealth += stealth

    n = len(results)
    return (total_effectiveness / n, total_stealth / n)


def compute_defender_fitness(
    results: list[MatchResult], config: Config
) -> tuple[float, float]:
    """Compute multi-objective defender fitness: (coverage, efficiency).

    coverage = mean across matchups of:
        (techniques_detected / max(techniques_attempted, 1)) * 50
        + attacks_prevented_by_response * prevention_value
        + (no_exfil_bonus if not data_exfiltrated else 0)

    efficiency =
        1.0 / (1.0 + total_false_positive_load)
        * (1.0 - rules_deployed / budget)
    """
    if not results:
        return (0.0, 0.0)

    w = config.scoring
    total_coverage = 0.0

    for r in results:
        attempted = max(r.techniques_attempted, 1)
        detection_rate = r.techniques_detected / attempted
        coverage = (
            detection_rate * 50.0
            + r.techniques_detected * w.detection_value
            + (w.no_exfil_bonus if not r.data_exfiltrated else 0.0)
        )
        total_coverage += coverage

    n = len(results)
    return (total_coverage / n, 0.5)  # Efficiency is computed at population level
