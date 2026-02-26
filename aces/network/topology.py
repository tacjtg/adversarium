"""Topology generators for network digital twins."""

from __future__ import annotations

import json
from pathlib import Path

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


class TopologyGenerator:
    """Factory for pre-built network topologies."""

    @staticmethod
    def corporate_medium() -> NetworkGraph:
        """Generate a 25-node corporate network topology.

        Segments:
            - DMZ: web-server, mail-server, vpn-gateway
            - User: 8 workstations
            - IT/Admin: 3 workstations
            - Server: DC, file-srv, app-srv, db-srv, backup-srv
            - Restricted: exec-ws-1, exec-ws-2, hr-srv
        """
        graph = NetworkGraph()

        # ── DMZ Segment (3 hosts) ──
        web_srv = Host(
            id="dmz-web-01",
            hostname="web-server",
            os=OSType.UBUNTU_22,
            role=HostRole.SERVER,
            criticality=0.3,
            services=[
                Service(name="http", port=80, version="nginx/1.24", exposed=True),
                Service(name="https", port=443, version="nginx/1.24", exposed=True),
                Service(name="ssh", port=22, version="8.9"),
            ],
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2023-44487",
                    cvss_score=7.5,
                    technique_enables="T1190",
                ),
            ],
            segment="dmz",
        )

        mail_srv = Host(
            id="dmz-mail-01",
            hostname="mail-server",
            os=OSType.UBUNTU_22,
            role=HostRole.SERVER,
            criticality=0.3,
            services=[
                Service(name="smtp", port=25, version="postfix/3.7", exposed=True),
                Service(name="imap", port=993, version="dovecot/2.3", exposed=True),
                Service(name="ssh", port=22, version="8.9"),
            ],
            segment="dmz",
        )

        vpn_gw = Host(
            id="dmz-vpn-01",
            hostname="vpn-gateway",
            os=OSType.RHEL_8,
            role=HostRole.SERVER,
            criticality=0.3,
            services=[
                Service(name="vpn", port=1194, version="openvpn/2.6", exposed=True),
                Service(name="ssh", port=22, version="8.2"),
            ],
            segment="dmz",
        )

        for h in [web_srv, mail_srv, vpn_gw]:
            graph.add_host(h)

        # ── User Segment (8 workstations) ──
        for i in range(1, 9):
            vulns = []
            if i in (3, 6):
                vulns = [
                    Vulnerability(
                        cve_id=f"CVE-2023-2868{i}",
                        cvss_score=7.8,
                        technique_enables="T1068",
                    )
                ]
            ws = HostFactory.workstation(
                id=f"usr-ws-{i:02d}",
                hostname=f"user-ws-{i}",
                criticality=0.15,
                segment="user",
                vulnerabilities=vulns,
            )
            graph.add_host(ws)

        # ── IT/Admin Segment (3 workstations) ──
        for i in range(1, 4):
            ws = HostFactory.workstation(
                id=f"it-ws-{i:02d}",
                hostname=f"it-admin-ws-{i}",
                os=OSType.WINDOWS_10,
                criticality=0.4,
                segment="it",
                has_credential_cache=True,
            )
            graph.add_host(ws)

        # ── Server Segment (5 hosts) ──
        dc = HostFactory.domain_controller(
            id="srv-dc-01",
            hostname="corp-dc-01",
            segment="server",
        )
        graph.add_host(dc)

        file_srv = HostFactory.server(
            id="srv-file-01",
            hostname="file-server",
            criticality=0.5,
            services=[
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            segment="server",
        )
        graph.add_host(file_srv)

        app_srv = HostFactory.server(
            id="srv-app-01",
            hostname="app-server",
            criticality=0.6,
            services=[
                Service(name="http", port=8080, version="tomcat/10.1"),
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            segment="server",
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2024-1001",
                    cvss_score=8.1,
                    technique_enables="T1210",
                ),
            ],
        )
        graph.add_host(app_srv)

        db_srv = HostFactory.database_server(
            id="srv-db-01",
            hostname="database-server",
            segment="server",
        )
        graph.add_host(db_srv)

        backup_srv = HostFactory.server(
            id="srv-backup-01",
            hostname="backup-server",
            criticality=0.9,
            os=OSType.UBUNTU_22,
            services=[
                Service(name="ssh", port=22, version="8.9"),
                Service(name="smb", port=445, version="4.18"),
            ],
            segment="server",
        )
        graph.add_host(backup_srv)

        # ── Restricted Segment (3 hosts) ──
        for i in range(1, 3):
            ws = HostFactory.workstation(
                id=f"rst-exec-{i:02d}",
                hostname=f"exec-ws-{i}",
                os=OSType.WINDOWS_10,
                criticality=0.6,
                segment="restricted",
            )
            graph.add_host(ws)

        hr_srv = HostFactory.server(
            id="rst-hr-01",
            hostname="hr-server",
            criticality=0.95,
            services=[
                Service(name="http", port=443, version="iis/10.0"),
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            segment="restricted",
        )
        hr_srv.high_value_data = True
        graph.add_host(hr_srv)

        # ── External node (internet) ──
        external = Host(
            id="external",
            hostname="internet",
            os=OSType.UBUNTU_22,
            role=HostRole.SERVER,
            criticality=0.0,
            segment="external",
        )
        graph.add_host(external)

        # ── Reachability Edges ──

        # External -> DMZ (specific exposed services)
        for dmz_id in ["dmz-web-01", "dmz-mail-01", "dmz-vpn-01"]:
            graph.add_edge("external", dmz_id, protocols=["http", "https", "smtp", "vpn"])

        # DMZ -> internal (limited: web server has path to user segment)
        graph.add_edge("dmz-web-01", "usr-ws-01", protocols=["http"])
        graph.add_edge("dmz-vpn-01", "it-ws-01", protocols=["rdp", "ssh"])

        # User segment -> server segment (SMB, HTTP)
        for i in range(1, 9):
            uid = f"usr-ws-{i:02d}"
            graph.add_edge(uid, "srv-file-01", protocols=["smb"])
            graph.add_edge(uid, "srv-app-01", protocols=["http"])
            graph.add_edge(uid, "srv-dc-01", protocols=["ldap", "kerberos"])
            # Users can reach each other
            for j in range(1, 9):
                if i != j:
                    graph.add_edge(uid, f"usr-ws-{j:02d}", protocols=["smb"])

        # IT segment -> everything (RDP, SSH, SMB)
        all_internal = (
            [f"usr-ws-{i:02d}" for i in range(1, 9)]
            + ["srv-dc-01", "srv-file-01", "srv-app-01", "srv-db-01", "srv-backup-01"]
            + ["rst-exec-01", "rst-exec-02", "rst-hr-01"]
            + ["dmz-web-01", "dmz-mail-01", "dmz-vpn-01"]
        )
        for i in range(1, 4):
            it_id = f"it-ws-{i:02d}"
            for target in all_internal:
                if target != it_id:
                    graph.add_edge(it_id, target, protocols=["rdp", "ssh", "smb"])
            # IT can reach each other
            for j in range(1, 4):
                if i != j:
                    graph.add_edge(it_id, f"it-ws-{j:02d}", protocols=["rdp", "ssh", "smb"])
            graph.add_edge(it_id, "srv-dc-01", protocols=["ldap", "kerberos", "rdp", "smb"])

        # Server segment internal reachability
        server_ids = ["srv-dc-01", "srv-file-01", "srv-app-01", "srv-db-01", "srv-backup-01"]
        for s1 in server_ids:
            for s2 in server_ids:
                if s1 != s2:
                    graph.add_edge(s1, s2, protocols=["smb", "rdp", "ssh"])

        # DC reachable from all internal via LDAP/Kerberos
        for uid in [f"usr-ws-{i:02d}" for i in range(1, 9)]:
            # Already added above, but ensure bidirectional for kerberos
            pass
        for rid in ["rst-exec-01", "rst-exec-02", "rst-hr-01"]:
            graph.add_edge(rid, "srv-dc-01", protocols=["ldap", "kerberos"])

        # Restricted segment reachable only from IT segment (already added)
        # Internal restricted connectivity
        for r1 in ["rst-exec-01", "rst-exec-02", "rst-hr-01"]:
            for r2 in ["rst-exec-01", "rst-exec-02", "rst-hr-01"]:
                if r1 != r2:
                    graph.add_edge(r1, r2, protocols=["smb"])

        # ── Credentials ──

        # Domain admin creds (cached on DC and one IT workstation)
        domain_admin = Credential(
            id="cred-domain-admin",
            username="da-admin",
            privilege=PrivLevel.ADMIN,
            valid_on=server_ids + [f"it-ws-{i:02d}" for i in range(1, 4)]
            + [f"usr-ws-{i:02d}" for i in range(1, 9)]
            + ["rst-exec-01", "rst-exec-02", "rst-hr-01"],
            compromised=False,
        )
        graph.add_credential(domain_admin)

        # Local admin on servers
        for srv_id in ["srv-file-01", "srv-app-01", "srv-db-01", "srv-backup-01"]:
            cred = Credential(
                id=f"cred-local-admin-{srv_id}",
                username=f"local-admin-{srv_id}",
                privilege=PrivLevel.ADMIN,
                valid_on=[srv_id],
            )
            graph.add_credential(cred)

        # Service account creds (cached on app and db servers)
        svc_cred = Credential(
            id="cred-svc-app-db",
            username="svc-app",
            privilege=PrivLevel.USER,
            valid_on=["srv-app-01", "srv-db-01"],
        )
        graph.add_credential(svc_cred)

        # Standard user creds on workstations
        for i in range(1, 9):
            cred = Credential(
                id=f"cred-user-{i:02d}",
                username=f"user{i:02d}",
                privilege=PrivLevel.USER,
                valid_on=[f"usr-ws-{i:02d}"],
            )
            graph.add_credential(cred)

        # IT admin user creds
        for i in range(1, 4):
            cred = Credential(
                id=f"cred-it-admin-{i:02d}",
                username=f"itadmin{i:02d}",
                privilege=PrivLevel.ADMIN,
                valid_on=[f"it-ws-{i:02d}"] + server_ids,
            )
            graph.add_credential(cred)

        # HR restricted creds
        hr_cred = Credential(
            id="cred-hr-admin",
            username="hr-admin",
            privilege=PrivLevel.ADMIN,
            valid_on=["rst-hr-01", "rst-exec-01", "rst-exec-02"],
        )
        graph.add_credential(hr_cred)

        return graph

    @staticmethod
    def to_json(graph: NetworkGraph, path: str | Path) -> None:
        """Export topology to JSON."""
        data = {
            "hosts": [],
            "edges": [],
            "credentials": [],
            "segments": graph.segments,
        }
        for host in graph.hosts.values():
            data["hosts"].append(host.model_dump())
        for src, dst, edge_data in graph.graph.edges(data=True):
            data["edges"].append({
                "source": src,
                "target": dst,
                "protocols": edge_data.get("protocols", []),
                "requires_credential": edge_data.get("requires_credential", False),
            })
        for cred in graph.credentials.values():
            data["credentials"].append(cred.model_dump())

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def from_json(path: str | Path) -> NetworkGraph:
        """Load topology from JSON file."""
        with open(path) as f:
            data = json.load(f)

        graph = NetworkGraph()
        for h_data in data["hosts"]:
            host = Host.model_validate(h_data)
            graph.add_host(host)
        for e_data in data["edges"]:
            graph.add_edge(
                e_data["source"],
                e_data["target"],
                e_data["protocols"],
                e_data.get("requires_credential", False),
            )
        for c_data in data["credentials"]:
            cred = Credential.model_validate(c_data)
            graph.add_credential(cred)

        return graph
