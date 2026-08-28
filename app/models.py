from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
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


class ScanEngine(Base):
    """One row per engine (nuclei/openvas) per scan. Each engine is tracked and
    fails/succeeds completely independently of the other."""

    __tablename__ = "scan_engine"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id"), nullable=False)
    engine: Mapped[str] = mapped_column(String(20), nullable=False)  # nuclei | openvas
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed|canceled
    progress: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    openvas_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="engines")


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
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
