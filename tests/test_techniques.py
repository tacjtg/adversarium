"""Phase 2 tests: ATT&CK technique registry."""

from aces.attack.techniques import (
    EffectType,
    PreconditionType,
    TechniqueRegistry,
)
from aces.config import Tactic


def setup_function():
    """Reset singleton before each test."""
    TechniqueRegistry.reset()


def test_registry_loads_all_techniques():
    """Registry contains all expected techniques (36 core + 2 optional = 38)."""
    registry = TechniqueRegistry()
    assert len(registry) >= 36
    # Check a few specific IDs exist
    assert "T1566.001" in registry
    assert "T1190" in registry
    assert "T1003.001" in registry
    assert "T1021.001" in registry
    assert "T1048" in registry


def test_initial_access_preconditions():
    """Initial access techniques require POSITION_EXTERNAL or CREDENTIAL_AVAILABLE."""
    registry = TechniqueRegistry()
    ia_techniques = registry.get_initial_access()
    assert len(ia_techniques) == 5

    for t in ia_techniques:
        precond_types = {p.type for p in t.preconditions}
        # Must require external position or credential
        assert (
            PreconditionType.POSITION_EXTERNAL in precond_types
            or PreconditionType.CREDENTIAL_AVAILABLE in precond_types
        ), f"{t.id} ({t.name}) missing position/credential precondition"


def test_lateral_movement_requires_credential_or_vuln():
    """Lateral movement techniques need either credential or vulnerability."""
    registry = TechniqueRegistry()
    lm_techniques = registry.get_by_tactic(Tactic.LATERAL_MOVEMENT)
    assert len(lm_techniques) == 5

    for t in lm_techniques:
        precond_types = {p.type for p in t.preconditions}
        has_cred = PreconditionType.CREDENTIAL_AVAILABLE in precond_types
        has_vuln = PreconditionType.VULNERABILITY_EXISTS in precond_types
        has_host = PreconditionType.POSITION_ON_HOST in precond_types
        assert has_cred or has_vuln or has_host, (
            f"{t.id} ({t.name}) has no cred/vuln/host precondition"
        )


def test_effect_types_present():
    """Techniques produce the expected effect types."""
    registry = TechniqueRegistry()

    # Phishing should grant foothold
    t = registry.get("T1566.001")
    effect_types = {e.type for e in t.effects}
    assert EffectType.GAIN_FOOTHOLD in effect_types

    # LSASS dump should harvest credentials
    t = registry.get("T1003.001")
    effect_types = {e.type for e in t.effects}
    assert EffectType.HARVEST_CREDENTIALS in effect_types

    # Scheduled task should establish persistence
    t = registry.get("T1053.005")
    effect_types = {e.type for e in t.effects}
    assert EffectType.ESTABLISH_PERSISTENCE in effect_types

    # RDP should move laterally
    t = registry.get("T1021.001")
    effect_types = {e.type for e in t.effects}
    assert EffectType.MOVE_LATERALLY in effect_types


def test_tactic_categorization():
    """Each technique is in exactly one tactic category."""
    registry = TechniqueRegistry()
    all_ids = set()
    for tactic in Tactic:
        tactic_ids = {t.id for t in registry.get_by_tactic(tactic)}
        # No overlap with previously seen IDs
        overlap = all_ids & tactic_ids
        assert not overlap, f"Techniques {overlap} appear in multiple tactics"
        all_ids.update(tactic_ids)
    # All techniques accounted for
    assert all_ids == set(registry.all_technique_ids())


def test_success_rates_in_range():
    """All base success rates are between 0 and 1."""
    registry = TechniqueRegistry()
    for t in registry.all_techniques():
        assert 0.0 <= t.base_success_rate <= 1.0, f"{t.id} has invalid success rate"
        assert 0.0 <= t.stealth_base <= 1.0, f"{t.id} has invalid stealth base"


def test_all_techniques_have_data_sources():
    """Every technique has at least one detection data source."""
    registry = TechniqueRegistry()
    for t in registry.all_techniques():
        assert len(t.common_data_sources) > 0, f"{t.id} has no data sources"


def test_tactic_coverage():
    """All major tactics have at least one technique."""
    registry = TechniqueRegistry()
    for tactic in Tactic:
        techniques = registry.get_by_tactic(tactic)
        assert len(techniques) >= 1, f"No techniques for tactic {tactic.value}"
