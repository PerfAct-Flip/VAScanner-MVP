from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "log": "Informational",
}


def normalize_severity(raw) -> str:
    return _SEVERITY_MAP.get(str(raw or "").strip().lower(), "Informational")


class Asset(Base):
    __tablename__ = "asset"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    # Populated from ARP data during discovery when the host is on the same
    # local network segment as the presence agent (not available across
    # routed subnets). Stable across DHCP lease renewals, so it's the
    # preferred key for recognizing "same device, new IP" — see the
    # discover-results matching logic in app/routers/agents.py.
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    # Strongest identity signal currently known for this asset: mac |
    # hostname | ip, in descending order of how safe it is to trust across
    # a DHCP lease change. Recomputed on every discovery sighting.
    identity_confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(50), nullable=True)
    criticality: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_targets: Mapped[list["ScanTarget"]] = relationship(back_populates="asset")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # internal | external
    status: Mapped[str] = mapped_column(String(20), default="queued")
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan_targets: Mapped[list["ScanTarget"]] = relationship(back_populates="scan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")
    engines: Mapped[list["ScanEngine"]] = relationship(back_populates="scan")
    credentials: Mapped[list["Credential"]] = relationship(back_populates="scan")


class ScanEngine(Base):
    """One row per engine (discover/nuclei/openvas) per scan. Each engine is
    tracked and fails/succeeds completely independently of the others.

    For an internal scan, `agent_id` pins the row to the one on-site Presence
    Agent that must service it (jobs are pre-assigned, never grabbed by
    whichever agent polls first, since each agent only has visibility into
    its own site's network). For an external scan it stays null — those
    engines still run in-process on the backend."""

    __tablename__ = "scan_engine"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    engine: Mapped[str] = mapped_column(String(20), nullable=False)  # discover | nuclei | openvas
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed|canceled
    progress: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    openvas_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agent.id"), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="engines")
    agent: Mapped["Agent | None"] = relationship()


class ScanEngineTarget(Base):
    """Per-target outcome of one engine run against one asset. Lets a retry
    re-attempt only the targets that actually failed instead of the whole
    engine's target list — a retried `ScanEngine` row is reset in place
    (same id, see POST /scans/{id}/retry), so these rows persist across a
    retry and `succeeded` ones are excluded from the next job build."""

    __tablename__ = "scan_engine_target"
    __table_args__ = (UniqueConstraint("scan_engine_id", "asset_id", name="uq_scan_engine_target"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_engine_id: Mapped[int] = mapped_column(ForeignKey("scan_engine.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # succeeded | failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ScanTarget(Base):
    __tablename__ = "scan_target"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="scan_targets")
    asset: Mapped["Asset"] = relationship(back_populates="scan_targets")


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), nullable=False)
    engine: Mapped[str] = mapped_column(String(20), nullable=False)  # nuclei | openvas
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cve: Mapped[str | None] = mapped_column(String(100), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    asset: Mapped["Asset"] = relationship(back_populates="findings")


class Agent(Base):
    __tablename__ = "agent"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # internal | external
    status: Mapped[str] = mapped_column(String(20), default="offline")
    # SHA-256 of the pairing key handed out once by POST /agents/register.
    # Never store the plaintext key — only this hash is compared against
    # what the agent presents on every subsequent authenticated call.
    api_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Credential(Base):
    """Scan-scoped authenticated-scan credential (SSH/WinRM/SNMP), used by the
    internal OpenVAS engine so it can run local security checks against
    discovered hosts rather than only unauthenticated network checks. The
    secret is symmetrically encrypted at rest (not hashed — the plaintext
    must be recoverable to hand to OpenVAS/the agent) via
    app.scanning.crypto, and is never returned by any API response."""

    __tablename__ = "credential"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    type: Mapped[str] = mapped_column(String(20), nullable=False)  # ssh | winrm | snmp
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="credentials")
