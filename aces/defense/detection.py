"""Detection logic types and helpers for defender genomes."""

from __future__ import annotations

from enum import Enum


class DetectionLogic(str, Enum):
    """Types of detection logic a defender can deploy."""

    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"
    ML_ANOMALY = "ml_anomaly"


class ResponseAction(str, Enum):
    """Active response actions a defender can take."""

    ALERT_ONLY = "alert_only"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    REVOKE_CREDENTIAL = "revoke_credential"
    BLOCK_TRAFFIC = "block_traffic"


# Deploy cost by detection logic type
DEPLOY_COSTS: dict[DetectionLogic, float] = {
    DetectionLogic.SIGNATURE: 1.0,
    DetectionLogic.BEHAVIORAL: 2.0,
    DetectionLogic.CORRELATION: 3.0,
    DetectionLogic.ML_ANOMALY: 2.5,
}
