"""ATT&CK technique registry with preconditions and effects."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from aces.config import Tactic


class PreconditionType(str, Enum):
    """Types of preconditions checked against simulation state."""

    POSITION_EXTERNAL = "position_external"
    POSITION_INTERNAL = "position_internal"
    POSITION_ON_HOST = "position_on_host"
    PRIVILEGE_USER = "privilege_user"
    PRIVILEGE_ADMIN = "privilege_admin"
    SERVICE_RUNNING = "service_running"
    VULNERABILITY_EXISTS = "vulnerability_exists"
    CREDENTIAL_AVAILABLE = "credential_available"
    HOST_NOT_ISOLATED = "host_not_isolated"
    OS_WINDOWS = "os_windows"
    OS_LINUX = "os_linux"
    HOST_IS_DC = "host_is_dc"
    HAS_CREDENTIAL_CACHE = "has_credential_cache"
    DATA_STAGED = "data_staged"
    HAS_INTERNET_ACCESS = "has_internet_access"


class EffectType(str, Enum):
    """Types of state changes applied on technique success."""

    GAIN_FOOTHOLD = "gain_foothold"
    ELEVATE_PRIVILEGE = "elevate_privilege"
    HARVEST_CREDENTIALS = "harvest_credentials"
    ESTABLISH_PERSISTENCE = "establish_persistence"
    MOVE_LATERALLY = "move_laterally"
    EXFILTRATE_DATA = "exfiltrate_data"
    EXECUTE_COMMAND = "execute_command"
    DISCOVER_HOSTS = "discover_hosts"
    REDUCE_DETECTION = "reduce_detection"
    INCREASE_STEALTH = "increase_stealth"
    STAGE_DATA = "stage_data"
    ENCRYPT_HOST = "encrypt_host"
    STOP_SERVICES = "stop_services"


@dataclass(frozen=True)
class Precondition:
    """A condition checked against simulation state."""

    type: PreconditionType
    service_name: str | None = None  # For SERVICE_RUNNING
    value: float = 0.0  # Generic parameter


@dataclass(frozen=True)
class Effect:
    """A state change applied on technique success."""

    type: EffectType
    privilege_level: str | None = None  # For GAIN_FOOTHOLD / ELEVATE_PRIVILEGE
    value: float = 0.0  # Generic parameter (e.g., stealth bonus amount)


@dataclass(frozen=True)
class TechniqueDef:
    """Definition of a MITRE ATT&CK technique for simulation."""

    id: str
    name: str
    tactic: Tactic
    preconditions: list[Precondition]
    effects: list[Effect]
    base_success_rate: float
    stealth_base: float
    common_data_sources: list[str]


class TechniqueRegistry:
    """Singleton registry of all modeled ATT&CK techniques."""

    _instance: TechniqueRegistry | None = None

    def __new__(cls) -> TechniqueRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._techniques = {}
            cls._instance._load_techniques()
        return cls._instance

    def __init__(self) -> None:
        # Already initialized in __new__
        pass

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None

    def _load_techniques(self) -> None:
        """Populate registry with all modeled techniques."""
        techniques = _build_technique_list()
        for t in techniques:
            self._techniques[t.id] = t

    def get(self, technique_id: str) -> TechniqueDef:
        """Get a technique by ID."""
        return self._techniques[technique_id]

    def get_by_tactic(self, tactic: Tactic) -> list[TechniqueDef]:
        """Get all techniques in a tactic."""
        return [t for t in self._techniques.values() if t.tactic == tactic]

    def get_initial_access(self) -> list[TechniqueDef]:
        """Get all initial access techniques."""
        return self.get_by_tactic(Tactic.INITIAL_ACCESS)

    def all_technique_ids(self) -> list[str]:
        """All registered technique IDs."""
        return list(self._techniques.keys())

    def all_techniques(self) -> list[TechniqueDef]:
        """All registered techniques."""
        return list(self._techniques.values())

    def __len__(self) -> int:
        return len(self._techniques)

    def __contains__(self, technique_id: str) -> bool:
        return technique_id in self._techniques


def _build_technique_list() -> list[TechniqueDef]:
    """Build the complete technique catalog from TECHNIQUES.md spec."""
    techniques: list[TechniqueDef] = []

    # ═══ INITIAL ACCESS ═══

    techniques.append(TechniqueDef(
        id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic=Tactic.INITIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_EXTERNAL),
        ],
        effects=[
            Effect(EffectType.GAIN_FOOTHOLD, privilege_level="user"),
        ],
        base_success_rate=0.35,
        stealth_base=0.6,
        common_data_sources=["Email Gateway", "Process Creation", "File Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic=Tactic.INITIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_EXTERNAL),
        ],
        effects=[
            Effect(EffectType.GAIN_FOOTHOLD, privilege_level="user"),
        ],
        base_success_rate=0.30,
        stealth_base=0.7,
        common_data_sources=["Web Proxy", "DNS", "Process Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic=Tactic.INITIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_EXTERNAL),
            Precondition(PreconditionType.VULNERABILITY_EXISTS),
        ],
        effects=[
            Effect(EffectType.GAIN_FOOTHOLD, privilege_level="user"),
        ],
        base_success_rate=0.70,
        stealth_base=0.4,
        common_data_sources=["Network Traffic", "Application Log", "Web Server Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1133",
        name="External Remote Services",
        tactic=Tactic.INITIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_EXTERNAL),
            Precondition(PreconditionType.CREDENTIAL_AVAILABLE),
        ],
        effects=[
            Effect(EffectType.GAIN_FOOTHOLD),  # privilege from credential
        ],
        base_success_rate=0.85,
        stealth_base=0.8,
        common_data_sources=["Authentication Log", "Network Connection"],
    ))

    techniques.append(TechniqueDef(
        id="T1078",
        name="Valid Accounts",
        tactic=Tactic.INITIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.CREDENTIAL_AVAILABLE),
        ],
        effects=[
            Effect(EffectType.GAIN_FOOTHOLD),  # privilege from credential
        ],
        base_success_rate=0.90,
        stealth_base=0.9,
        common_data_sources=["Authentication Log", "Account Usage Audit"],
    ))

    # ═══ EXECUTION ═══

    techniques.append(TechniqueDef(
        id="T1059.001",
        name="Command and Scripting: PowerShell",
        tactic=Tactic.EXECUTION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXECUTE_COMMAND),
        ],
        base_success_rate=0.85,
        stealth_base=0.5,
        common_data_sources=["Script Execution", "Process Creation", "Command Line"],
    ))

    techniques.append(TechniqueDef(
        id="T1059.004",
        name="Command and Scripting: Unix Shell",
        tactic=Tactic.EXECUTION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_LINUX),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXECUTE_COMMAND),
        ],
        base_success_rate=0.90,
        stealth_base=0.6,
        common_data_sources=["Process Creation", "Command Line Audit"],
    ))

    techniques.append(TechniqueDef(
        id="T1047",
        name="Windows Management Instrumentation",
        tactic=Tactic.EXECUTION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.EXECUTE_COMMAND),
        ],
        base_success_rate=0.80,
        stealth_base=0.65,
        common_data_sources=["WMI Trace", "Process Creation"],
    ))

    # ═══ PERSISTENCE ═══

    techniques.append(TechniqueDef(
        id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=Tactic.PERSISTENCE,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.ESTABLISH_PERSISTENCE),
        ],
        base_success_rate=0.80,
        stealth_base=0.5,
        common_data_sources=["Scheduled Task Creation", "Process Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1543.003",
        name="Create or Modify System Process: Windows Service",
        tactic=Tactic.PERSISTENCE,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.ESTABLISH_PERSISTENCE),
        ],
        base_success_rate=0.75,
        stealth_base=0.4,
        common_data_sources=["Service Creation", "Windows Registry"],
    ))

    techniques.append(TechniqueDef(
        id="T1136.001",
        name="Create Account: Local Account",
        tactic=Tactic.PERSISTENCE,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.ESTABLISH_PERSISTENCE),
            Effect(EffectType.HARVEST_CREDENTIALS),
        ],
        base_success_rate=0.90,
        stealth_base=0.3,
        common_data_sources=["Account Creation", "Security Log"],
    ))

    # ═══ PRIVILEGE ESCALATION ═══

    techniques.append(TechniqueDef(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
            Precondition(PreconditionType.VULNERABILITY_EXISTS),
        ],
        effects=[
            Effect(EffectType.ELEVATE_PRIVILEGE, privilege_level="admin"),
        ],
        base_success_rate=0.60,
        stealth_base=0.4,
        common_data_sources=["Process Creation", "Exploit Guard"],
    ))

    techniques.append(TechniqueDef(
        id="T1548.002",
        name="Abuse Elevation Control: Bypass UAC",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.ELEVATE_PRIVILEGE, privilege_level="admin"),
        ],
        base_success_rate=0.65,
        stealth_base=0.55,
        common_data_sources=["Process Creation", "Windows Registry"],
    ))

    techniques.append(TechniqueDef(
        id="T1134",
        name="Access Token Manipulation",
        tactic=Tactic.PRIVILEGE_ESCALATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.ELEVATE_PRIVILEGE, privilege_level="system"),
        ],
        base_success_rate=0.75,
        stealth_base=0.6,
        common_data_sources=["API Monitoring", "Access Token"],
    ))

    # ═══ DEFENSE EVASION ═══

    techniques.append(TechniqueDef(
        id="T1070.001",
        name="Indicator Removal: Clear Windows Event Logs",
        tactic=Tactic.DEFENSE_EVASION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.REDUCE_DETECTION, value=0.3),
        ],
        base_success_rate=0.90,
        stealth_base=0.2,
        common_data_sources=["Log Deletion Event", "Security Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic=Tactic.DEFENSE_EVASION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.INCREASE_STEALTH, value=0.15),
        ],
        base_success_rate=0.85,
        stealth_base=0.7,
        common_data_sources=["File Analysis", "Script Execution"],
    ))

    techniques.append(TechniqueDef(
        id="T1218.011",
        name="System Binary Proxy Execution: Rundll32",
        tactic=Tactic.DEFENSE_EVASION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXECUTE_COMMAND),
            Effect(EffectType.INCREASE_STEALTH, value=0.2),
        ],
        base_success_rate=0.80,
        stealth_base=0.75,
        common_data_sources=["Process Creation", "Module Load"],
    ))

    # ═══ CREDENTIAL ACCESS ═══

    techniques.append(TechniqueDef(
        id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=Tactic.CREDENTIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.OS_WINDOWS),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
            Precondition(PreconditionType.HAS_CREDENTIAL_CACHE),
        ],
        effects=[
            Effect(EffectType.HARVEST_CREDENTIALS),
        ],
        base_success_rate=0.85,
        stealth_base=0.3,
        common_data_sources=["Process Access (LSASS)", "Sensor Health"],
    ))

    techniques.append(TechniqueDef(
        id="T1003.003",
        name="OS Credential Dumping: NTDS",
        tactic=Tactic.CREDENTIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.HOST_IS_DC),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.HARVEST_CREDENTIALS),  # All domain creds
        ],
        base_success_rate=0.80,
        stealth_base=0.2,
        common_data_sources=["File Access", "Volume Shadow Copy", "Command Line"],
    ))

    techniques.append(TechniqueDef(
        id="T1558.003",
        name="Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic=Tactic.CREDENTIAL_ACCESS,
        preconditions=[
            Precondition(PreconditionType.POSITION_INTERNAL),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.HARVEST_CREDENTIALS),
        ],
        base_success_rate=0.75,
        stealth_base=0.65,
        common_data_sources=["Kerberos Traffic", "Authentication Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=Tactic.CREDENTIAL_ACCESS,
        preconditions=[],  # Can be used externally or internally
        effects=[
            Effect(EffectType.HARVEST_CREDENTIALS),
        ],
        base_success_rate=0.20,
        stealth_base=0.4,
        common_data_sources=["Authentication Log", "Account Lockout"],
    ))

    # ═══ DISCOVERY ═══

    techniques.append(TechniqueDef(
        id="T1018",
        name="Remote System Discovery",
        tactic=Tactic.DISCOVERY,
        preconditions=[
            Precondition(PreconditionType.POSITION_INTERNAL),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.DISCOVER_HOSTS),
        ],
        base_success_rate=0.95,
        stealth_base=0.7,
        common_data_sources=["Network Traffic", "Process Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1083",
        name="File and Directory Discovery",
        tactic=Tactic.DISCOVERY,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.STAGE_DATA),  # Identifies high-value data
        ],
        base_success_rate=0.95,
        stealth_base=0.85,
        common_data_sources=["Process Creation", "Command Line"],
    ))

    techniques.append(TechniqueDef(
        id="T1087.002",
        name="Account Discovery: Domain Account",
        tactic=Tactic.DISCOVERY,
        preconditions=[
            Precondition(PreconditionType.POSITION_INTERNAL),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.DISCOVER_HOSTS),
        ],
        base_success_rate=0.90,
        stealth_base=0.7,
        common_data_sources=["LDAP Query", "Authentication Log"],
    ))

    # ═══ LATERAL MOVEMENT ═══

    techniques.append(TechniqueDef(
        id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        tactic=Tactic.LATERAL_MOVEMENT,
        preconditions=[
            Precondition(PreconditionType.SERVICE_RUNNING, service_name="rdp"),
            Precondition(PreconditionType.CREDENTIAL_AVAILABLE),
            Precondition(PreconditionType.HOST_NOT_ISOLATED),
        ],
        effects=[
            Effect(EffectType.MOVE_LATERALLY),
        ],
        base_success_rate=0.85,
        stealth_base=0.6,
        common_data_sources=["Network Connection", "Authentication Log", "RDP Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic=Tactic.LATERAL_MOVEMENT,
        preconditions=[
            Precondition(PreconditionType.SERVICE_RUNNING, service_name="smb"),
            Precondition(PreconditionType.CREDENTIAL_AVAILABLE),
            Precondition(PreconditionType.HOST_NOT_ISOLATED),
        ],
        effects=[
            Effect(EffectType.MOVE_LATERALLY),
        ],
        base_success_rate=0.80,
        stealth_base=0.5,
        common_data_sources=["Network Share Access", "SMB Traffic", "Authentication Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1021.004",
        name="Remote Services: SSH",
        tactic=Tactic.LATERAL_MOVEMENT,
        preconditions=[
            Precondition(PreconditionType.SERVICE_RUNNING, service_name="ssh"),
            Precondition(PreconditionType.CREDENTIAL_AVAILABLE),
            Precondition(PreconditionType.HOST_NOT_ISOLATED),
        ],
        effects=[
            Effect(EffectType.MOVE_LATERALLY),
        ],
        base_success_rate=0.85,
        stealth_base=0.65,
        common_data_sources=["SSH Log", "Authentication Log", "Network Connection"],
    ))

    techniques.append(TechniqueDef(
        id="T1570",
        name="Lateral Tool Transfer",
        tactic=Tactic.LATERAL_MOVEMENT,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
            Precondition(PreconditionType.HOST_NOT_ISOLATED),
        ],
        effects=[
            Effect(EffectType.EXECUTE_COMMAND),
        ],
        base_success_rate=0.75,
        stealth_base=0.5,
        common_data_sources=["Network Traffic", "File Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1210",
        name="Exploitation of Remote Services",
        tactic=Tactic.LATERAL_MOVEMENT,
        preconditions=[
            Precondition(PreconditionType.VULNERABILITY_EXISTS),
            Precondition(PreconditionType.HOST_NOT_ISOLATED),
        ],
        effects=[
            Effect(EffectType.MOVE_LATERALLY),
        ],
        base_success_rate=0.55,
        stealth_base=0.35,
        common_data_sources=["Network Traffic", "IDS/IPS", "Application Log"],
    ))

    # ═══ COLLECTION ═══

    techniques.append(TechniqueDef(
        id="T1005",
        name="Data from Local System",
        tactic=Tactic.COLLECTION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.STAGE_DATA),
        ],
        base_success_rate=0.90,
        stealth_base=0.75,
        common_data_sources=["File Access", "Process Creation"],
    ))

    techniques.append(TechniqueDef(
        id="T1039",
        name="Data from Network Shared Drive",
        tactic=Tactic.COLLECTION,
        preconditions=[
            Precondition(PreconditionType.POSITION_INTERNAL),
            Precondition(PreconditionType.PRIVILEGE_USER),
            Precondition(PreconditionType.SERVICE_RUNNING, service_name="smb"),
        ],
        effects=[
            Effect(EffectType.STAGE_DATA),
        ],
        base_success_rate=0.85,
        stealth_base=0.7,
        common_data_sources=["Network Share Access", "File Access"],
    ))

    # ═══ EXFILTRATION ═══

    techniques.append(TechniqueDef(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic=Tactic.EXFILTRATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.DATA_STAGED),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXFILTRATE_DATA),
        ],
        base_success_rate=0.75,
        stealth_base=0.5,
        common_data_sources=["Network Traffic", "DNS", "Firewall Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic=Tactic.EXFILTRATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.DATA_STAGED),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXFILTRATE_DATA),
        ],
        base_success_rate=0.80,
        stealth_base=0.6,
        common_data_sources=["Network Traffic", "Proxy Log"],
    ))

    techniques.append(TechniqueDef(
        id="T1567.002",
        name="Exfiltration Over Web Service: Cloud Storage",
        tactic=Tactic.EXFILTRATION,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.DATA_STAGED),
            Precondition(PreconditionType.PRIVILEGE_USER),
        ],
        effects=[
            Effect(EffectType.EXFILTRATE_DATA),
        ],
        base_success_rate=0.85,
        stealth_base=0.7,
        common_data_sources=["Cloud API Log", "Network Traffic", "Web Proxy"],
    ))

    # ═══ IMPACT (Optional Extension) ═══

    techniques.append(TechniqueDef(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic=Tactic.IMPACT,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.ENCRYPT_HOST),
        ],
        base_success_rate=0.90,
        stealth_base=0.1,
        common_data_sources=["File Modification", "Service Stop"],
    ))

    techniques.append(TechniqueDef(
        id="T1489",
        name="Service Stop",
        tactic=Tactic.IMPACT,
        preconditions=[
            Precondition(PreconditionType.POSITION_ON_HOST),
            Precondition(PreconditionType.PRIVILEGE_ADMIN),
        ],
        effects=[
            Effect(EffectType.STOP_SERVICES),
        ],
        base_success_rate=0.95,
        stealth_base=0.2,
        common_data_sources=["Service Activity", "Process Termination"],
    ))

    return techniques
