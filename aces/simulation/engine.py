"""Core simulation engine: executes attacker vs defender matchups."""

from __future__ import annotations

import random as _random_module

from aces.attack.genome import AttackGene, AttackGenome, TargetSelector
from aces.attack.techniques import (
    EffectType,
    PreconditionType,
    TechniqueDef,
    TechniqueRegistry,
)
from aces.config import Config
from aces.defense.detection import ResponseAction
from aces.defense.genome import DefenseGenome, DetectionGene
from aces.network.assets import HostRole, PrivLevel
from aces.network.graph import NetworkGraph
from aces.simulation.state import EventOutcome, MatchResult, SimEvent, SimulationState


class SimulationEngine:
    """Executes a single matchup between an attacker and defender."""

    def __init__(self, registry: TechniqueRegistry, rng: _random_module.Random | None = None) -> None:
        self.registry = registry
        self.rng = rng or _random_module.Random()

    def simulate(
        self,
        attacker: AttackGenome,
        defender: DefenseGenome,
        network: NetworkGraph,
    ) -> MatchResult:
        """Execute one attacker-vs-defender matchup."""
        state = SimulationState(network)
        result = MatchResult(
            attacker_id=str(id(attacker)),
            defender_id=str(id(defender)),
        )

        consecutive_successes = 0
        max_consecutive = 0

        for step, gene in enumerate(attacker.genes):
            result.techniques_attempted += 1
            tech = self.registry.get(gene.technique_id)

            # Resolve target
            target_id = self._resolve_target(gene, state, tech)
            if target_id is None:
                # Try fallback
                if gene.fallback_technique and gene.fallback_technique in self.registry:
                    fallback_tech = self.registry.get(gene.fallback_technique)
                    target_id = self._resolve_target(gene, state, fallback_tech)
                    if target_id is not None:
                        tech = fallback_tech

            if target_id is None:
                state.record_event(SimEvent(
                    step=step,
                    technique_id=gene.technique_id,
                    target_host="none",
                    outcome=EventOutcome.PRECONDITION_FAILURE,
                ))
                consecutive_successes = 0
                continue

            # Check preconditions
            if not self._check_preconditions(tech, target_id, state):
                # Try fallback
                if gene.fallback_technique and gene.fallback_technique in self.registry:
                    fallback_tech = self.registry.get(gene.fallback_technique)
                    if self._check_preconditions(fallback_tech, target_id, state):
                        tech = fallback_tech
                    else:
                        state.record_event(SimEvent(
                            step=step,
                            technique_id=gene.technique_id,
                            target_host=target_id,
                            outcome=EventOutcome.PRECONDITION_FAILURE,
                        ))
                        consecutive_successes = 0
                        continue
                else:
                    state.record_event(SimEvent(
                        step=step,
                        technique_id=gene.technique_id,
                        target_host=target_id,
                        outcome=EventOutcome.PRECONDITION_FAILURE,
                    ))
                    consecutive_successes = 0
                    continue

            # Roll success based on base_success_rate
            if self.rng.random() > tech.base_success_rate:
                state.record_event(SimEvent(
                    step=step,
                    technique_id=tech.id,
                    target_host=target_id,
                    outcome=EventOutcome.PRECONDITION_FAILURE,
                    effects={"reason": "technique_failed"},
                ))
                consecutive_successes = 0
                continue

            # Check defender detection
            effective_stealth = gene.stealth_modifier + state.stealth_bonus
            effective_stealth = min(1.0, effective_stealth)

            # Apply detection reduction for this host
            host_reduction = state.detection_reduction.get(target_id, 0.0)

            detected, matching_rule = self._check_detection(
                tech.id, effective_stealth, defender, host_reduction
            )

            if detected and matching_rule is not None:
                result.techniques_detected += 1
                self._apply_response(matching_rule.response_action, target_id, state)
                state.record_event(SimEvent(
                    step=step,
                    technique_id=tech.id,
                    target_host=target_id,
                    outcome=EventOutcome.DETECTED,
                    detection_rule=matching_rule.technique_detected,
                    response_action=matching_rule.response_action.value,
                ))
                consecutive_successes = 0
                continue

            # Technique succeeds — apply effects
            effects = self._apply_effects(tech, target_id, gene, state)
            result.techniques_successful += 1
            consecutive_successes += 1
            max_consecutive = max(max_consecutive, consecutive_successes)

            state.record_event(SimEvent(
                step=step,
                technique_id=tech.id,
                target_host=target_id,
                outcome=EventOutcome.SUCCESS,
                effects=effects,
            ))

        # Compute result metrics
        result.hosts_compromised = len(state.compromised_hosts)
        result.credentials_obtained = len(state.obtained_credentials)
        result.data_exfiltrated = state.data_exfiltrated
        result.kill_chain_length = max_consecutive
        result.events = state.events

        if state.compromised_hosts:
            result.max_criticality_reached = max(
                state.network.get_host(h).criticality
                for h in state.compromised_hosts
            )

        return result

    def _resolve_target(
        self,
        gene: AttackGene,
        state: SimulationState,
        tech: TechniqueDef,
    ) -> str | None:
        """Resolve target host based on gene's target_selector."""
        # For initial access from external, target must be reachable from external
        needs_external = any(
            p.type == PreconditionType.POSITION_EXTERNAL for p in tech.preconditions
        )

        if needs_external and state.attacker_position is not None:
            return None  # Already internal, can't use external technique

        reachable = state.get_reachable_hosts()
        if not reachable:
            return None

        # Filter out already-compromised hosts for foothold techniques
        # (but allow targeting compromised hosts for priv esc, cred access, etc.)
        foothold_effects = {EffectType.GAIN_FOOTHOLD, EffectType.MOVE_LATERALLY}
        is_foothold = any(e.type in foothold_effects for e in tech.effects)
        if is_foothold:
            candidates = [h for h in reachable if h not in state.compromised_hosts and h != "external"]
        else:
            # For non-foothold, prefer compromised hosts (working on host already owned)
            has_on_host = any(
                p.type == PreconditionType.POSITION_ON_HOST for p in tech.preconditions
            )
            if has_on_host and state.compromised_hosts:
                candidates = [h for h in state.compromised_hosts if h not in state.isolated_hosts]
            else:
                candidates = [h for h in reachable if h != "external"]

        if not candidates:
            return None

        selector = gene.target_selector

        if selector == TargetSelector.HIGHEST_CRITICALITY:
            candidates.sort(key=lambda h: state.network.get_host(h).criticality, reverse=True)
            return candidates[0]

        elif selector == TargetSelector.MOST_CONNECTED:
            candidates.sort(
                key=lambda h: len(state.network.get_reachable(h)), reverse=True
            )
            return candidates[0]

        elif selector == TargetSelector.SPECIFIC_ROLE and gene.target_role:
            role_matches = [
                h for h in candidates
                if state.network.get_host(h).role == gene.target_role
            ]
            return role_matches[0] if role_matches else self.rng.choice(candidates)

        elif selector == TargetSelector.LEAST_DEFENDED:
            return self.rng.choice(candidates)

        else:  # RANDOM_REACHABLE or fallback
            return self.rng.choice(candidates)

    def _check_preconditions(
        self,
        tech: TechniqueDef,
        target_id: str,
        state: SimulationState,
    ) -> bool:
        """Check if all preconditions are satisfied."""
        host = state.network.get_host(target_id)

        for precond in tech.preconditions:
            ptype = precond.type

            if ptype == PreconditionType.POSITION_EXTERNAL:
                if state.attacker_position is not None:
                    return False

            elif ptype == PreconditionType.POSITION_INTERNAL:
                if state.attacker_position is None and not state.compromised_hosts:
                    return False

            elif ptype == PreconditionType.POSITION_ON_HOST:
                if target_id not in state.compromised_hosts:
                    return False

            elif ptype == PreconditionType.PRIVILEGE_USER:
                priv = state.get_attacker_privilege(target_id)
                if priv < PrivLevel.USER:
                    # Allow if we're gaining foothold (priv will be set)
                    if target_id not in state.compromised_hosts:
                        return False

            elif ptype == PreconditionType.PRIVILEGE_ADMIN:
                priv = state.get_attacker_privilege(target_id)
                if priv < PrivLevel.ADMIN:
                    return False

            elif ptype == PreconditionType.SERVICE_RUNNING:
                if precond.service_name and not host.has_service(precond.service_name):
                    return False

            elif ptype == PreconditionType.VULNERABILITY_EXISTS:
                if not host.has_vulnerability_for(tech.id):
                    return False

            elif ptype == PreconditionType.CREDENTIAL_AVAILABLE:
                has_cred = any(
                    cred_id not in state.revoked_credentials
                    and target_id in state.network.credentials[cred_id].valid_on
                    for cred_id in state.obtained_credentials
                )
                if not has_cred:
                    return False

            elif ptype == PreconditionType.HOST_NOT_ISOLATED:
                if target_id in state.isolated_hosts:
                    return False

            elif ptype == PreconditionType.OS_WINDOWS:
                if not host.is_windows():
                    return False

            elif ptype == PreconditionType.OS_LINUX:
                if not host.is_linux():
                    return False

            elif ptype == PreconditionType.HOST_IS_DC:
                if host.role != HostRole.DOMAIN_CONTROLLER:
                    return False

            elif ptype == PreconditionType.HAS_CREDENTIAL_CACHE:
                if not host.has_credential_cache:
                    return False

            elif ptype == PreconditionType.DATA_STAGED:
                if not host.data_staged:
                    return False

        return True

    def _check_detection(
        self,
        technique_id: str,
        stealth_modifier: float,
        defender: DefenseGenome,
        host_reduction: float = 0.0,
    ) -> tuple[bool, DetectionGene | None]:
        """Check if defender detects this technique."""
        prob, matching_rule = defender.get_detection_probability(
            technique_id, stealth_modifier
        )
        # Apply host-level detection reduction (from log clearing)
        prob = max(0.0, prob - host_reduction)

        if prob <= 0.0 or matching_rule is None:
            return False, None

        detected = self.rng.random() < prob
        return detected, matching_rule if detected else None

    def _apply_response(
        self,
        response: ResponseAction,
        target_host: str,
        state: SimulationState,
    ) -> None:
        """Apply defender's response action."""
        if response == ResponseAction.ISOLATE_HOST:
            state.isolated_hosts.add(target_host)
        elif response == ResponseAction.REVOKE_CREDENTIAL:
            # Revoke any credentials the attacker used on this host
            for cred_id in list(state.obtained_credentials):
                cred = state.network.credentials.get(cred_id)
                if cred and target_host in cred.valid_on:
                    state.revoked_credentials.add(cred_id)
        elif response == ResponseAction.KILL_PROCESS:
            pass  # Process killed, technique already failed
        elif response == ResponseAction.BLOCK_TRAFFIC:
            pass  # Traffic blocked for this technique

    def _apply_effects(
        self,
        tech: TechniqueDef,
        target_id: str,
        gene: AttackGene,
        state: SimulationState,
    ) -> dict:
        """Apply technique effects to simulation state."""
        effects: dict = {}
        host = state.network.get_host(target_id)

        for effect in tech.effects:
            if effect.type == EffectType.GAIN_FOOTHOLD:
                priv = PrivLevel.USER
                if effect.privilege_level == "admin":
                    priv = PrivLevel.ADMIN
                elif effect.privilege_level == "system":
                    priv = PrivLevel.SYSTEM
                # If using credential, inherit credential's privilege
                if any(p.type == PreconditionType.CREDENTIAL_AVAILABLE for p in tech.preconditions):
                    for cred_id in state.obtained_credentials:
                        cred = state.network.credentials.get(cred_id)
                        if cred and target_id in cred.valid_on and cred_id not in state.revoked_credentials:
                            if cred.privilege >= priv:
                                priv = cred.privilege
                            break

                state.network.compromise_host(target_id, priv)
                state.compromised_hosts.add(target_id)
                state.attacker_position = target_id
                effects["compromised"] = target_id
                effects["privilege"] = priv.value

            elif effect.type == EffectType.ELEVATE_PRIVILEGE:
                priv = PrivLevel.ADMIN
                if effect.privilege_level == "system":
                    priv = PrivLevel.SYSTEM
                state.network.compromise_host(target_id, priv)
                effects["elevated"] = priv.value

            elif effect.type == EffectType.HARVEST_CREDENTIALS:
                harvested = state.network.harvest_credentials(target_id)
                for cred in harvested:
                    if cred.id not in state.revoked_credentials:
                        state.obtained_credentials.add(cred.id)
                        cred.compromised = True
                effects["credentials_harvested"] = len(harvested)

            elif effect.type == EffectType.ESTABLISH_PERSISTENCE:
                state.persistence_hosts.add(target_id)
                effects["persistence"] = target_id

            elif effect.type == EffectType.MOVE_LATERALLY:
                priv = PrivLevel.USER
                # Inherit credential privilege
                for cred_id in state.obtained_credentials:
                    cred = state.network.credentials.get(cred_id)
                    if cred and target_id in cred.valid_on and cred_id not in state.revoked_credentials:
                        if cred.privilege >= priv:
                            priv = cred.privilege
                        break

                state.network.compromise_host(target_id, priv)
                state.compromised_hosts.add(target_id)
                state.attacker_position = target_id
                effects["moved_to"] = target_id
                effects["privilege"] = priv.value

            elif effect.type == EffectType.EXFILTRATE_DATA:
                state.data_exfiltrated = True
                effects["exfiltrated"] = True

            elif effect.type == EffectType.EXECUTE_COMMAND:
                effects["command_executed"] = True

            elif effect.type == EffectType.DISCOVER_HOSTS:
                # Reveal hosts in same segment
                segment = host.segment
                if segment and segment in state.network.segments:
                    effects["discovered_hosts"] = state.network.segments[segment]

            elif effect.type == EffectType.REDUCE_DETECTION:
                state.detection_reduction[target_id] = (
                    state.detection_reduction.get(target_id, 0.0) + effect.value
                )
                effects["detection_reduced"] = effect.value

            elif effect.type == EffectType.INCREASE_STEALTH:
                state.stealth_bonus += effect.value
                effects["stealth_bonus"] = effect.value

            elif effect.type == EffectType.STAGE_DATA:
                host.data_staged = True
                effects["data_staged"] = True

            elif effect.type == EffectType.ENCRYPT_HOST:
                effects["encrypted"] = True

            elif effect.type == EffectType.STOP_SERVICES:
                effects["services_stopped"] = True

        return effects
