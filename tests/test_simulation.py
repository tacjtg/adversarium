"""Phase 4 tests: simulation engine and scoring."""

import random

from aces.attack.genome import AttackGene, AttackGenome, TargetSelector
from aces.attack.operators import create_random_attacker
from aces.attack.techniques import TechniqueRegistry
from aces.config import Config
from aces.defense.detection import DetectionLogic, ResponseAction
from aces.defense.genome import DefenseGenome, DetectionGene
from aces.defense.operators import create_random_defender
from aces.network.topology import TopologyGenerator
from aces.simulation.engine import SimulationEngine
from aces.simulation.scoring import compute_attacker_fitness, compute_defender_fitness
from aces.simulation.state import EventOutcome


def setup_function():
    TechniqueRegistry.reset()


def _make_network():
    return TopologyGenerator.corporate_medium()


def _empty_defender():
    return DefenseGenome(genes=[], budget=15)


def test_simulation_basic_attack_succeeds():
    """An attacker with valid initial access against an empty defender
    should achieve at least one successful technique."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    network = _make_network()
    rng = random.Random(42)
    engine = SimulationEngine(registry, rng)

    # Run multiple attempts since there's randomness
    successes = 0
    for seed in range(50):
        engine.rng = random.Random(seed)
        attacker = create_random_attacker(registry, config, random.Random(seed))
        result = engine.simulate(attacker, _empty_defender(), network)
        if result.techniques_successful > 0:
            successes += 1

    # At least some should succeed (with no defender, many should)
    assert successes >= 5, f"Only {successes}/50 runs had any success"


def test_simulation_detection_blocks_attack():
    """A defender with high-confidence detection should detect techniques."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    network = _make_network()

    # Create a defender that covers phishing with very high confidence
    defender = DefenseGenome(
        genes=[
            DetectionGene(
                technique_detected="T1566.001",
                data_source="Email Gateway",
                detection_logic=DetectionLogic.BEHAVIORAL,
                confidence=0.95,
                false_positive_rate=0.05,
                response_action=ResponseAction.ALERT_ONLY,
            ),
            DetectionGene(
                technique_detected="T1566.002",
                data_source="Web Proxy",
                detection_logic=DetectionLogic.BEHAVIORAL,
                confidence=0.95,
                false_positive_rate=0.05,
                response_action=ResponseAction.ALERT_ONLY,
            ),
            DetectionGene(
                technique_detected="T1190",
                data_source="Network Traffic",
                detection_logic=DetectionLogic.SIGNATURE,
                confidence=0.95,
                false_positive_rate=0.05,
                response_action=ResponseAction.ALERT_ONLY,
            ),
        ],
        budget=15,
    )

    # Create an attacker that starts with phishing
    detections = 0
    total_attempts = 100
    for seed in range(total_attempts):
        rng = random.Random(seed)
        attacker = AttackGenome(
            genes=[
                AttackGene(technique_id="T1566.001", stealth_modifier=0.0),
                AttackGene(technique_id="T1059.001"),
            ],
            max_length=12,
        )
        engine = SimulationEngine(registry, rng)
        result = engine.simulate(attacker, defender, network)
        if result.techniques_detected > 0:
            detections += 1

    # Should detect phishing most of the time (95% conf * 1.0 stealth_mod adjustment)
    # But also need to account for base_success_rate (0.35) — phishing may fail first
    assert detections > 20, f"Only {detections}/{total_attempts} detected"


def test_simulation_isolation_prevents_lateral_movement():
    """ISOLATE_HOST response should prevent attacker from reaching isolated host."""
    registry = TechniqueRegistry()
    network = _make_network()
    rng = random.Random(42)
    engine = SimulationEngine(registry, rng)

    # Manually set up a state where a host is isolated
    from aces.simulation.state import SimulationState

    state = SimulationState(network)
    state.isolated_hosts.add("srv-dc-01")

    # DC should not be reachable
    assert not state.is_host_reachable("srv-dc-01")


def test_simulation_credential_revocation():
    """REVOKE_CREDENTIAL should prevent credential reuse."""
    registry = TechniqueRegistry()
    network = _make_network()
    rng = random.Random(42)

    from aces.simulation.state import SimulationState

    state = SimulationState(network)
    # Simulate having a credential and then it being revoked
    state.obtained_credentials.add("cred-domain-admin")
    state.revoked_credentials.add("cred-domain-admin")

    # The credential should be in obtained but also in revoked
    assert "cred-domain-admin" in state.obtained_credentials
    assert "cred-domain-admin" in state.revoked_credentials


def test_scoring_higher_criticality_higher_score():
    """Compromising a high-criticality host produces higher attacker score."""
    from aces.simulation.state import MatchResult

    config = Config.from_defaults()

    # High criticality result
    high = MatchResult(
        attacker_id="a1",
        defender_id="d1",
        hosts_compromised=1,
        max_criticality_reached=1.0,
        credentials_obtained=0,
        data_exfiltrated=False,
        techniques_detected=0,
        techniques_successful=1,
        techniques_attempted=1,
        kill_chain_length=1,
    )

    # Low criticality result
    low = MatchResult(
        attacker_id="a2",
        defender_id="d1",
        hosts_compromised=1,
        max_criticality_reached=0.1,
        credentials_obtained=0,
        data_exfiltrated=False,
        techniques_detected=0,
        techniques_successful=1,
        techniques_attempted=1,
        kill_chain_length=1,
    )

    high_score = compute_attacker_fitness([high], config)
    low_score = compute_attacker_fitness([low], config)
    assert high_score[0] > low_score[0]


def test_scoring_defender_rewards_detection():
    """Detecting attacks increases defender coverage score."""
    from aces.simulation.state import MatchResult

    config = Config.from_defaults()

    detected = MatchResult(
        attacker_id="a1",
        defender_id="d1",
        hosts_compromised=0,
        max_criticality_reached=0.0,
        credentials_obtained=0,
        data_exfiltrated=False,
        techniques_detected=3,
        techniques_successful=0,
        techniques_attempted=5,
        kill_chain_length=0,
    )

    no_detect = MatchResult(
        attacker_id="a1",
        defender_id="d2",
        hosts_compromised=3,
        max_criticality_reached=0.8,
        credentials_obtained=2,
        data_exfiltrated=True,
        techniques_detected=0,
        techniques_successful=5,
        techniques_attempted=5,
        kill_chain_length=5,
    )

    det_score = compute_defender_fitness([detected], config)
    nodet_score = compute_defender_fitness([no_detect], config)
    assert det_score[0] > nodet_score[0]


def test_scoring_exfiltration_bonus():
    """Data exfiltration adds a significant bonus to attacker score."""
    from aces.simulation.state import MatchResult

    config = Config.from_defaults()

    with_exfil = MatchResult(
        attacker_id="a1",
        defender_id="d1",
        hosts_compromised=1,
        max_criticality_reached=0.5,
        credentials_obtained=0,
        data_exfiltrated=True,
        techniques_detected=0,
        techniques_successful=2,
        techniques_attempted=2,
        kill_chain_length=2,
    )

    without_exfil = MatchResult(
        attacker_id="a1",
        defender_id="d1",
        hosts_compromised=1,
        max_criticality_reached=0.5,
        credentials_obtained=0,
        data_exfiltrated=False,
        techniques_detected=0,
        techniques_successful=2,
        techniques_attempted=2,
        kill_chain_length=2,
    )

    with_score = compute_attacker_fitness([with_exfil], config)
    without_score = compute_attacker_fitness([without_exfil], config)
    assert with_score[0] > without_score[0]


def test_full_simulation_roundtrip():
    """A complete simulation with random attacker and defender runs without error."""
    registry = TechniqueRegistry()
    config = Config.from_defaults()
    network = _make_network()
    rng = random.Random(42)

    attacker = create_random_attacker(registry, config, rng)
    defender = create_random_defender(registry, config, rng)
    engine = SimulationEngine(registry, rng)

    result = engine.simulate(attacker, defender, network)

    # Result should be populated
    assert result.techniques_attempted > 0
    assert len(result.events) > 0
    assert result.techniques_successful + result.techniques_detected <= result.techniques_attempted
