"""NetworkX-based network graph model."""

from __future__ import annotations

import copy

import networkx as nx

from aces.network.assets import Credential, Host, HostRole, PrivLevel


class NetworkGraph:
    """Graph-based network model wrapping networkx.DiGraph.

    Each node stores a Host object. Edges represent reachability
    with protocol and credential requirements.
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self.credentials: dict[str, Credential] = {}
        self.segments: dict[str, list[str]] = {}
        self._hosts: dict[str, Host] = {}

    def add_host(self, host: Host) -> None:
        """Add a host node to the graph."""
        self._hosts[host.id] = host
        self.graph.add_node(host.id, host=host)
        # Track segment membership
        if host.segment:
            self.segments.setdefault(host.segment, [])
            if host.id not in self.segments[host.segment]:
                self.segments[host.segment].append(host.id)

    def add_edge(
        self,
        src: str,
        dst: str,
        protocols: list[str],
        requires_credential: bool = False,
    ) -> None:
        """Add a directed reachability edge."""
        segment_boundary = False
        src_host = self._hosts.get(src)
        dst_host = self._hosts.get(dst)
        if src_host and dst_host and src_host.segment != dst_host.segment:
            segment_boundary = True
        self.graph.add_edge(
            src,
            dst,
            protocols=protocols,
            requires_credential=requires_credential,
            segment_boundary=segment_boundary,
        )

    def add_credential(self, credential: Credential) -> None:
        """Register a credential in the network."""
        self.credentials[credential.id] = credential

    def get_host(self, host_id: str) -> Host:
        """Get a host by ID."""
        return self._hosts[host_id]

    def get_reachable(self, host_id: str, protocol: str | None = None) -> list[str]:
        """Get hosts reachable from host_id, optionally filtered by protocol."""
        reachable = []
        for _, target, data in self.graph.out_edges(host_id, data=True):
            if protocol is None or protocol in data.get("protocols", []):
                reachable.append(target)
        return reachable

    def get_attack_surface(self, host_id: str) -> list[tuple[str, list[str]]]:
        """Returns (target_id, available_protocols) for all reachable targets."""
        surface = []
        for _, target, data in self.graph.out_edges(host_id, data=True):
            surface.append((target, data.get("protocols", [])))
        return surface

    def compromise_host(self, host_id: str, priv_level: PrivLevel) -> None:
        """Mark host as compromised at given privilege level."""
        host = self._hosts[host_id]
        host.is_compromised = True
        if priv_level >= host.privilege_level:
            host.privilege_level = priv_level

    def get_hosts_by_role(self, role: HostRole) -> list[Host]:
        """Get all hosts with a specific role."""
        return [h for h in self._hosts.values() if h.role == role]

    def get_compromised_hosts(self) -> list[Host]:
        """Get all compromised hosts."""
        return [h for h in self._hosts.values() if h.is_compromised]

    def harvest_credentials(self, host_id: str) -> list[Credential]:
        """Return credentials cached on this host."""
        host = self._hosts[host_id]
        if not host.has_credential_cache:
            return []
        return [
            cred
            for cred in self.credentials.values()
            if host_id in cred.valid_on or any(
                h_id == host_id for h_id in cred.valid_on
            )
        ]

    def get_credentials_for_host(self, target_id: str) -> list[Credential]:
        """Return all credentials valid on a target host."""
        return [
            cred
            for cred in self.credentials.values()
            if target_id in cred.valid_on
        ]

    @property
    def hosts(self) -> dict[str, Host]:
        """All hosts in the graph."""
        return self._hosts

    @property
    def host_count(self) -> int:
        return len(self._hosts)

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def clone(self) -> NetworkGraph:
        """Deep copy for simulation. Copies all mutable state."""
        new = NetworkGraph()
        new.graph = self.graph.copy()
        new._hosts = {k: v.model_copy(deep=True) for k, v in self._hosts.items()}
        new.credentials = {k: v.model_copy(deep=True) for k, v in self.credentials.items()}
        new.segments = copy.deepcopy(self.segments)
        # Update node references to point to cloned hosts
        for host_id, host in new._hosts.items():
            new.graph.nodes[host_id]["host"] = host
        return new
