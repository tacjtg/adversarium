"""Mutable simulation state for a single attacker-vs-defender matchup."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from aces.network.assets import PrivLevel
from aces.network.graph import NetworkGraph


class EventOutcome(str, Enum):
    """Possible outcomes for a simulation step."""

    SUCCESS = "success"
    DETECTED = "detected"
    PRECONDITION_FAILURE = "precondition_failure"


@dataclass
class SimEvent:
    """Record of a single simulation step."""

    step: int
    technique_id: str
    target_host: str
    outcome: EventOutcome
    detection_rule: str | None = None
    response_action: str | None = None
    effects: dict = field(default_factory=dict)


@dataclass
class MatchResult:
    """Result of a single attacker-vs-defender matchup."""

    attacker_id: str
    defender_id: str
    attacker_score: float = 0.0
    defender_score: float = 0.0
    events: list[SimEvent] = field(default_factory=list)
    hosts_compromised: int = 0
    max_criticality_reached: float = 0.0
    credentials_obtained: int = 0
    data_exfiltrated: bool = False
    techniques_detected: int = 0
    techniques_successful: int = 0
    techniques_attempted: int = 0
    kill_chain_length: int = 0


class SimulationState:
    """Mutable state for a single attacker-vs-defender matchup.

    Wraps a cloned NetworkGraph and tracks attacker progress.
    """

    def __init__(self, network: NetworkGraph) -> None:
        self.network = network.clone()
        self.attacker_position: str | None = None  # None = external
        self.compromised_hosts: set[str] = set()
        self.obtained_credentials: set[str] = set()
        self.persistence_hosts: set[str] = set()
        self.data_exfiltrated: bool = False
        self.isolated_hosts: set[str] = set()
        self.revoked_credentials: set[str] = set()
        self.events: list[SimEvent] = []
        self.stealth_bonus: float = 0.0  # From defense evasion techniques
        self.detection_reduction: dict[str, float] = {}  # host_id -> reduction

    def is_host_reachable(self, target_id: str) -> bool:
        """Check if target is reachable from current position."""
        if target_id in self.isolated_hosts:
            return False

        if self.attacker_position is None:
            # External — can only reach hosts reachable from "external"
            reachable = self.network.get_reachable("external")
            return target_id in reachable

        # Internal — check graph reachability from current position
        reachable = self.network.get_reachable(self.attacker_position)
        # Also reachable from any compromised host
        for comp_id in self.compromised_hosts:
            if comp_id not in self.isolated_hosts:
                reachable.extend(self.network.get_reachable(comp_id))

        return target_id in reachable

    def get_attacker_privilege(self, host_id: str) -> PrivLevel:
        """Current privilege level on a host."""
        if host_id not in self.compromised_hosts:
            return PrivLevel.NONE
        return self.network.get_host(host_id).privilege_level

    def get_reachable_hosts(self) -> list[str]:
        """Get all hosts reachable from current position."""
        reachable: set[str] = set()

        if self.attacker_position is None:
            reachable.update(self.network.get_reachable("external"))
        else:
            reachable.update(self.network.get_reachable(self.attacker_position))

        for comp_id in self.compromised_hosts:
            if comp_id not in self.isolated_hosts:
                reachable.update(self.network.get_reachable(comp_id))

        # Remove isolated hosts
        reachable -= self.isolated_hosts
        return list(reachable)

    def record_event(self, event: SimEvent) -> None:
        """Record a simulation event."""
        self.events.append(event)
