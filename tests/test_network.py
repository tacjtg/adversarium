"""Phase 1 tests: network layer."""

from aces.network.assets import (
    Credential,
    Host,
    HostFactory,
    HostRole,
    OSType,
    PrivLevel,
    Service,
    Vulnerability,
)
from aces.network.graph import NetworkGraph
from aces.network.topology import TopologyGenerator


def test_host_creation():
    """Hosts can be created with all required fields."""
    host = Host(
        id="test-01",
        hostname="test-host",
        os=OSType.WINDOWS_10,
        role=HostRole.WORKSTATION,
        criticality=0.5,
        services=[Service(name="smb", port=445, version="3.1.1")],
    )
    assert host.id == "test-01"
    assert host.hostname == "test-host"
    assert host.os == OSType.WINDOWS_10
    assert host.role == HostRole.WORKSTATION
    assert host.criticality == 0.5
    assert not host.is_compromised
    assert host.privilege_level == PrivLevel.NONE
    assert host.has_service("smb")
    assert not host.has_service("rdp")
    assert host.is_windows()
    assert not host.is_linux()


def test_host_factory():
    """HostFactory produces valid hosts for each type."""
    ws = HostFactory.workstation(id="ws-01", hostname="ws-1")
    assert ws.role == HostRole.WORKSTATION
    assert ws.has_service("smb")

    dc = HostFactory.domain_controller(id="dc-01")
    assert dc.role == HostRole.DOMAIN_CONTROLLER
    assert dc.has_service("ldap")
    assert dc.has_service("kerberos")
    assert dc.criticality == 1.0

    db = HostFactory.database_server(id="db-01")
    assert db.role == HostRole.DATABASE
    assert db.has_service("sql")

    fw = HostFactory.firewall(id="fw-01")
    assert fw.role == HostRole.FIREWALL


def test_graph_add_hosts_and_edges():
    """Graph construction produces correct node/edge counts."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1")
    h2 = HostFactory.workstation(id="h2", hostname="host-2")
    h3 = HostFactory.server(id="h3", hostname="host-3")

    graph.add_host(h1)
    graph.add_host(h2)
    graph.add_host(h3)
    graph.add_edge("h1", "h2", protocols=["smb"])
    graph.add_edge("h1", "h3", protocols=["smb", "rdp"])

    assert graph.host_count == 3
    assert graph.edge_count == 2


def test_graph_reachability():
    """get_reachable returns only directly connected hosts for given protocol."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1")
    h2 = HostFactory.workstation(id="h2", hostname="host-2")
    h3 = HostFactory.server(id="h3", hostname="host-3")

    graph.add_host(h1)
    graph.add_host(h2)
    graph.add_host(h3)
    graph.add_edge("h1", "h2", protocols=["smb"])
    graph.add_edge("h1", "h3", protocols=["rdp"])

    # Without filter
    reachable = graph.get_reachable("h1")
    assert set(reachable) == {"h2", "h3"}

    # With protocol filter
    assert graph.get_reachable("h1", "smb") == ["h2"]
    assert graph.get_reachable("h1", "rdp") == ["h3"]
    assert graph.get_reachable("h1", "ssh") == []

    # h2 cannot reach h1 (directed graph)
    assert graph.get_reachable("h2") == []


def test_graph_clone_independence():
    """Mutating a cloned graph does not affect the original."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1")
    graph.add_host(h1)

    clone = graph.clone()
    clone.compromise_host("h1", PrivLevel.ADMIN)

    assert clone.get_host("h1").is_compromised
    assert clone.get_host("h1").privilege_level == PrivLevel.ADMIN
    assert not graph.get_host("h1").is_compromised
    assert graph.get_host("h1").privilege_level == PrivLevel.NONE


def test_graph_compromise_host():
    """compromise_host updates privilege level correctly."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1")
    graph.add_host(h1)

    graph.compromise_host("h1", PrivLevel.USER)
    assert graph.get_host("h1").is_compromised
    assert graph.get_host("h1").privilege_level == PrivLevel.USER

    # Elevate privilege
    graph.compromise_host("h1", PrivLevel.ADMIN)
    assert graph.get_host("h1").privilege_level == PrivLevel.ADMIN

    # Lower privilege does not downgrade
    graph.compromise_host("h1", PrivLevel.USER)
    assert graph.get_host("h1").privilege_level == PrivLevel.ADMIN


def test_corporate_medium_topology():
    """Default topology has correct structure."""
    graph = TopologyGenerator.corporate_medium()

    # 22 internal hosts + 1 external node = 23
    # DMZ(3) + User(8) + IT(3) + Server(5) + Restricted(3) + External(1)
    assert graph.host_count == 23

    # Check segments
    assert "dmz" in graph.segments
    assert "user" in graph.segments
    assert "it" in graph.segments
    assert "server" in graph.segments
    assert "restricted" in graph.segments

    assert len(graph.segments["dmz"]) == 3
    assert len(graph.segments["user"]) == 8
    assert len(graph.segments["it"]) == 3
    assert len(graph.segments["server"]) == 5
    assert len(graph.segments["restricted"]) == 3

    # DC exists and is high criticality
    dcs = graph.get_hosts_by_role(HostRole.DOMAIN_CONTROLLER)
    assert len(dcs) == 1
    assert dcs[0].criticality == 1.0

    # DB server exists
    dbs = graph.get_hosts_by_role(HostRole.DATABASE)
    assert len(dbs) == 1
    assert dbs[0].criticality == 0.9

    # Credentials exist
    assert len(graph.credentials) > 0
    # Domain admin credential exists
    assert "cred-domain-admin" in graph.credentials

    # External can reach DMZ
    reachable_from_ext = graph.get_reachable("external")
    assert "dmz-web-01" in reachable_from_ext


def test_credential_harvesting():
    """harvest_credentials returns creds cached on compromised host."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1", has_credential_cache=True)
    graph.add_host(h1)

    cred = Credential(
        id="cred-1",
        username="user1",
        privilege=PrivLevel.USER,
        valid_on=["h1", "h2"],
    )
    graph.add_credential(cred)

    harvested = graph.harvest_credentials("h1")
    assert len(harvested) == 1
    assert harvested[0].id == "cred-1"


def test_topology_json_roundtrip(tmp_path):
    """Topology can be exported and re-imported from JSON."""
    graph = TopologyGenerator.corporate_medium()
    json_path = tmp_path / "test_topo.json"

    TopologyGenerator.to_json(graph, str(json_path))
    loaded = TopologyGenerator.from_json(str(json_path))

    assert loaded.host_count == graph.host_count
    assert len(loaded.credentials) == len(graph.credentials)


def test_priv_level_ordering():
    """PrivLevel comparisons work correctly."""
    assert PrivLevel.SYSTEM >= PrivLevel.ADMIN
    assert PrivLevel.ADMIN >= PrivLevel.USER
    assert PrivLevel.USER >= PrivLevel.NONE
    assert PrivLevel.SYSTEM > PrivLevel.NONE
    assert not (PrivLevel.NONE > PrivLevel.USER)
    assert PrivLevel.NONE < PrivLevel.USER
    assert PrivLevel.ADMIN <= PrivLevel.SYSTEM


def test_attack_surface():
    """get_attack_surface returns target/protocol tuples."""
    graph = NetworkGraph()
    h1 = HostFactory.workstation(id="h1", hostname="host-1")
    h2 = HostFactory.workstation(id="h2", hostname="host-2")
    h3 = HostFactory.server(id="h3", hostname="host-3")

    graph.add_host(h1)
    graph.add_host(h2)
    graph.add_host(h3)
    graph.add_edge("h1", "h2", protocols=["smb"])
    graph.add_edge("h1", "h3", protocols=["smb", "rdp"])

    surface = graph.get_attack_surface("h1")
    assert len(surface) == 2
    targets = {t[0] for t in surface}
    assert targets == {"h2", "h3"}
