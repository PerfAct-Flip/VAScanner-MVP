from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

EngineName = Literal["nuclei", "openvas"]
ScanType = Literal["internal", "external"]
ScanEngineChoice = Literal["discover", "nuclei", "openvas"]


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
    mac_address: str | None
    identity_confidence: str | None
    open_ports: str | None
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
    # Which engines to run. Omit entirely (None) to get the legacy default
    # set for this scan type. Selecting "openvas" with no credential is
    # deliberately NOT rejected here — it's a predictable, recoverable
    # situation (see create_scan/job_complete), not a hard error: the engine
    # is just quietly not queued, and the response's `warnings` list tells
    # the caller why instead of the scan failing outright.
    engines: list[ScanEngineChoice] | None = None

    @model_validator(mode="after")
    def validate_by_type(self):
        if self.engines is not None and not self.engines:
            raise ValueError("engines, if provided, must contain at least one engine.")

        if self.type == "internal":
            if not self.agent_id:
                raise ValueError("agent_id is required for internal scans (the on-site Presence Agent to run it).")
            if self.engines is not None:
                if "discover" not in self.engines and not self.asset_ids:
                    raise ValueError("asset_ids must be provided when 'discover' is not among the selected engines.")
        else:
            if self.agent_id is not None:
                raise ValueError("agent_id is only valid for internal scans.")
            if self.credentials:
                raise ValueError("credentials are only used by internal scans.")
            if not self.asset_ids:
                raise ValueError("asset_ids must contain at least one asset id.")
            if self.engines is not None and "discover" in self.engines:
                raise ValueError("discover is only valid for internal scans.")
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
    requested_engines: str | None
    engines: list[ScanEngineOut] = []
    # Non-fatal heads-up about this scan (e.g. "OpenVAS needs a credential
    # to run and was skipped", "example.com does not resolve via DNS right
    # now") — never populated from the ORM object, only set by the endpoint
    # that creates/returns a scan, and empty for every other read of a scan.
    warnings: list[str] = []


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
    cvss_score: float | None
    port: int | None
    created_at: datetime


class ScanFindingsOut(BaseModel):
    scan_id: int
    nuclei: list[FindingOut]
    openvas: list[FindingOut]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class PciCompanyInfo(BaseModel):
    company: str
    contact_name: str
    job_title: str
    telephone: str
    email: str
    address: str
    city: str | None = None
    state: str | None = None
    postal_code: str | None = None
    country: str | None = None
    url: str | None = None


class PciReportInfo(BaseModel):
    customer: PciCompanyInfo
    asv: PciCompanyInfo
    asv_certificate_number: str
    scan_report_type: Literal["Full scan", "Partial scan"] = "Full scan"


class ReportCreate(BaseModel):
    scan_id: int | None = None
    format: Literal["csv", "pdf", "pci"]
    # Required (and only meaningful) when format == "pci" — this app has no
    # customer/tenant model, so the scan-customer and ASV company details
    # that populate the attestation sections are supplied per-report rather
    # than stored anywhere.
    pci_info: PciReportInfo | None = None

    @model_validator(mode="after")
    def validate_pci(self):
        if self.format == "pci":
            if self.pci_info is None:
                raise ValueError("pci_info is required when format is 'pci'.")
            if self.scan_id is None:
                raise ValueError("scan_id is required when format is 'pci' — a PCI ASV report is scoped to one scan.")
        return self


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None
    format: str
    finding_count: int
    generated_at: datetime


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
    mac_address: str | None = None
    open_ports: list[int] = []


class JobFindingIn(BaseModel):
    asset_id: int
    severity: str
    cve: str | None = None
    description: str | None = None
    recommendation: str | None = None
    cvss_score: float | None = None
    port: int | None = None


class JobTargetResultIn(BaseModel):
    asset_id: int
    status: str  # succeeded | failed
    error_message: str | None = None


class JobResultsIn(BaseModel):
    hosts: list[DiscoveredHost] | None = None
    findings: list[JobFindingIn] | None = None
    target_results: list[JobTargetResultIn] | None = None


class JobProgressIn(BaseModel):
    progress: str | None = None
    progress_pct: int | None = None


class JobCompleteIn(BaseModel):
    status: Literal["completed", "failed"]
    error_message: str | None = None
