"""Network asset models: hosts, services, vulnerabilities, credentials."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class OSType(str, Enum):
    """Operating system types."""

    WINDOWS_10 = "windows_10"
    WINDOWS_SERVER_2019 = "windows_server_2019"
    UBUNTU_22 = "ubuntu_22"
    RHEL_8 = "rhel_8"


class HostRole(str, Enum):
    """Functional role of a host."""

    WORKSTATION = "workstation"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    FIREWALL = "firewall"
    DATABASE = "database"


class PrivLevel(str, Enum):
    """Privilege levels, ordered from lowest to highest."""

    NONE = "none"
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, PrivLevel):
            return NotImplemented
        order = {PrivLevel.NONE: 0, PrivLevel.USER: 1, PrivLevel.ADMIN: 2, PrivLevel.SYSTEM: 3}
        return order[self] >= order[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, PrivLevel):
            return NotImplemented
        order = {PrivLevel.NONE: 0, PrivLevel.USER: 1, PrivLevel.ADMIN: 2, PrivLevel.SYSTEM: 3}
        return order[self] > order[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, PrivLevel):
            return NotImplemented
        order = {PrivLevel.NONE: 0, PrivLevel.USER: 1, PrivLevel.ADMIN: 2, PrivLevel.SYSTEM: 3}
        return order[self] <= order[other]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, PrivLevel):
            return NotImplemented
        order = {PrivLevel.NONE: 0, PrivLevel.USER: 1, PrivLevel.ADMIN: 2, PrivLevel.SYSTEM: 3}
        return order[self] < order[other]


class Service(BaseModel):
    """A network service running on a host."""

    model_config = ConfigDict(frozen=False)

    name: str
    port: int
    version: str = ""
    exposed: bool = False


class Vulnerability(BaseModel):
    """A vulnerability present on a host."""

    model_config = ConfigDict(frozen=False)

    cve_id: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    technique_enables: str  # ATT&CK technique ID
    exploited: bool = False


class Credential(BaseModel):
    """An authentication credential."""

    model_config = ConfigDict(frozen=False)

    id: str
    username: str
    privilege: PrivLevel
    valid_on: list[str]  # Host IDs
    compromised: bool = False


class Host(BaseModel):
    """A network host in the digital twin."""

    model_config = ConfigDict(frozen=False)

    id: str
    hostname: str
    os: OSType
    role: HostRole
    criticality: float = Field(ge=0.0, le=1.0)
    services: list[Service] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    installed_software: list[str] = Field(default_factory=list)
    is_compromised: bool = False
    privilege_level: PrivLevel = PrivLevel.NONE
    has_credential_cache: bool = False
    segment: str = ""
    high_value_data: bool = False
    data_staged: bool = False

    def has_service(self, service_name: str) -> bool:
        """Check if host runs a service by name."""
        return any(s.name == service_name for s in self.services)

    def has_vulnerability_for(self, technique_id: str) -> Vulnerability | None:
        """Return vulnerability enabling a technique, or None."""
        for v in self.vulnerabilities:
            if v.technique_enables == technique_id and not v.exploited:
                return v
        return None

    def is_windows(self) -> bool:
        return self.os in (OSType.WINDOWS_10, OSType.WINDOWS_SERVER_2019)

    def is_linux(self) -> bool:
        return self.os in (OSType.UBUNTU_22, OSType.RHEL_8)


class HostFactory:
    """Factory methods for creating realistic hosts."""

    @staticmethod
    def workstation(
        id: str,
        hostname: str,
        os: OSType = OSType.WINDOWS_10,
        criticality: float = 0.2,
        segment: str = "user",
        vulnerabilities: list[Vulnerability] | None = None,
        has_credential_cache: bool = True,
    ) -> Host:
        return Host(
            id=id,
            hostname=hostname,
            os=os,
            role=HostRole.WORKSTATION,
            criticality=criticality,
            services=[
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            vulnerabilities=vulnerabilities or [],
            installed_software=["office", "browser", "email_client"],
            has_credential_cache=has_credential_cache,
            segment=segment,
        )

    @staticmethod
    def server(
        id: str,
        hostname: str,
        os: OSType = OSType.WINDOWS_SERVER_2019,
        role: HostRole = HostRole.SERVER,
        criticality: float = 0.5,
        services: list[Service] | None = None,
        segment: str = "server",
        vulnerabilities: list[Vulnerability] | None = None,
        has_credential_cache: bool = True,
    ) -> Host:
        default_services = [
            Service(name="smb", port=445, version="3.1.1"),
            Service(name="rdp", port=3389, version="10.0"),
        ]
        return Host(
            id=id,
            hostname=hostname,
            os=os,
            role=role,
            criticality=criticality,
            services=services or default_services,
            vulnerabilities=vulnerabilities or [],
            has_credential_cache=has_credential_cache,
            segment=segment,
        )

    @staticmethod
    def domain_controller(
        id: str,
        hostname: str = "dc-01",
        criticality: float = 1.0,
        segment: str = "server",
    ) -> Host:
        return Host(
            id=id,
            hostname=hostname,
            os=OSType.WINDOWS_SERVER_2019,
            role=HostRole.DOMAIN_CONTROLLER,
            criticality=criticality,
            services=[
                Service(name="ldap", port=389, version=""),
                Service(name="kerberos", port=88, version=""),
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="dns", port=53, version=""),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            has_credential_cache=True,
            segment=segment,
            high_value_data=True,
        )

    @staticmethod
    def database_server(
        id: str,
        hostname: str = "db-srv-01",
        criticality: float = 0.9,
        segment: str = "server",
    ) -> Host:
        return Host(
            id=id,
            hostname=hostname,
            os=OSType.WINDOWS_SERVER_2019,
            role=HostRole.DATABASE,
            criticality=criticality,
            services=[
                Service(name="sql", port=1433, version="2019"),
                Service(name="smb", port=445, version="3.1.1"),
                Service(name="rdp", port=3389, version="10.0"),
            ],
            has_credential_cache=True,
            segment=segment,
            high_value_data=True,
        )

    @staticmethod
    def firewall(
        id: str,
        hostname: str = "fw-01",
        criticality: float = 0.3,
        segment: str = "dmz",
    ) -> Host:
        return Host(
            id=id,
            hostname=hostname,
            os=OSType.RHEL_8,
            role=HostRole.FIREWALL,
            criticality=criticality,
            services=[
                Service(name="ssh", port=22, version="8.9"),
            ],
            segment=segment,
        )
