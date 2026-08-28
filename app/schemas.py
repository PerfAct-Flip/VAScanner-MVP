from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

EngineName = Literal["nuclei", "openvas"]
ScanType = Literal["internal", "external"]


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


class AssetCreate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    environment: str | None = None
    criticality: str | None = None

    @model_validator(mode="after")
    def require_target(self):
        if not self.hostname and not self.ip_address:
            raise ValueError("Provide at least one of hostname or ip_address.")
        return self

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v):
        if not v:
            return v
        import ipaddress

        ipaddress.ip_address(v)
        return v


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str | None
    ip_address: str | None
    environment: str | None
    criticality: str | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    type: ScanType
    asset_ids: list[int]

    @field_validator("asset_ids")
    @classmethod
    def non_empty(cls, v):
        if not v:
            raise ValueError("asset_ids must contain at least one asset id.")
        return v


class ScanEngineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    engine: str
    status: str
    progress: str | None
    progress_pct: int
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    status: str
    start_time: datetime | None
    end_time: datetime | None
    created_at: datetime
    engines: list[ScanEngineOut] = []


class ScanEngineStatusOut(BaseModel):
    status: str
    progress: str
    progress_pct: int
    error_message: str | None
    findings_count: int
    started_at: str | None
    finished_at: str | None


class ScanStatusOut(BaseModel):
    scan_id: int
    overall_status: str
    engines: dict[str, ScanEngineStatusOut]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    asset_id: int
    engine: str
    severity: str
    cve: str | None
    description: str | None
    recommendation: str | None
    created_at: datetime


class ScanFindingsOut(BaseModel):
    scan_id: int
    nuclei: list[FindingOut]
    openvas: list[FindingOut]


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------


class AgentHeartbeat(BaseModel):
    name: str
    type: Literal["internal", "external"]


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    status: str
    last_seen: datetime
