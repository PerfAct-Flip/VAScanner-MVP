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


class CredentialCreate(BaseModel):
    type: Literal["ssh", "winrm", "snmp"]
    username: str
    secret: str
    port: int | None = None


class ScanCreate(BaseModel):
    type: ScanType
    asset_ids: list[int] = []
    agent_id: int | None = None
    credentials: list[CredentialCreate] = []

    @model_validator(mode="after")
    def validate_by_type(self):
        if self.type == "internal":
            if not self.agent_id:
                raise ValueError("agent_id is required for internal scans (the on-site Presence Agent to run it).")
        else:
            if self.agent_id is not None:
                raise ValueError("agent_id is only valid for internal scans.")
            if self.credentials:
                raise ValueError("credentials are only used by internal scans.")
            if not self.asset_ids:
                raise ValueError("asset_ids must contain at least one asset id.")
        return self


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


class AgentRegisterIn(BaseModel):
    name: str
    type: Literal["internal", "external"]


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    status: str
    last_seen: datetime


class AgentRegisterOut(AgentOut):
    # Shown exactly once, at registration time. Only its hash is ever stored.
    api_key: str


# ---------------------------------------------------------------------------
# Agent job queue (internal scans)
# ---------------------------------------------------------------------------


class JobTargetOut(BaseModel):
    asset_id: int
    hostname: str | None
    ip_address: str | None


class JobCredentialOut(BaseModel):
    type: str
    username: str
    secret: str
    port: int | None


class JobOut(BaseModel):
    scan_engine_id: int
    scan_id: int
    engine: str
    targets: list[JobTargetOut] = []
    credentials: list[JobCredentialOut] = []


class DiscoveredHost(BaseModel):
    ip_address: str
    hostname: str | None = None


class JobFindingIn(BaseModel):
    asset_id: int
    severity: str
    cve: str | None = None
    description: str | None = None
    recommendation: str | None = None


class JobResultsIn(BaseModel):
    hosts: list[DiscoveredHost] | None = None
    findings: list[JobFindingIn] | None = None


class JobProgressIn(BaseModel):
    progress: str | None = None
    progress_pct: int | None = None


class JobCompleteIn(BaseModel):
    status: Literal["completed", "failed"]
    error_message: str | None = None
