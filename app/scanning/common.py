import ipaddress
import socket
import threading
from datetime import datetime, timezone

# Scan ids that have been requested to cancel. Checked cooperatively by each
# engine runner between targets/polls; never force-killed mid-request.
CANCELLED_SCANS: set[int] = set()
_CANCEL_LOCK = threading.Lock()


def request_cancel(scan_id: int) -> None:
    with _CANCEL_LOCK:
        CANCELLED_SCANS.add(scan_id)


def is_cancelled(scan_id: int) -> bool:
    with _CANCEL_LOCK:
        return scan_id in CANCELLED_SCANS


def clear_cancel(scan_id: int) -> None:
    with _CANCEL_LOCK:
        CANCELLED_SCANS.discard(scan_id)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def dns_resolves(target: str) -> bool:
    """True if target is a literal IP, or a hostname that currently
    resolves. Never raises — used for advance warnings, not to gate
    whether a scan is allowed to run."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def validate_target(target: str) -> None:
    """Raise if target is unresolvable. Shared by both engines."""
    if not dns_resolves(target):
        raise Exception(f"'{target}' does not resolve via DNS — check the hostname is correct and reachable.")


def already_succeeded_targets(db, scan_engine_id: int) -> set[int]:
    """Asset ids this engine already succeeded against on a prior run of
    the same ScanEngine row (a retry resets status in place rather than
    creating a new row). Used to skip re-scanning — and re-recording
    findings for — a target that already passed."""
    from app.models import ScanEngineTarget

    return {
        row.asset_id
        for row in db.query(ScanEngineTarget).filter_by(scan_engine_id=scan_engine_id, status="succeeded").all()
    }


def record_target_result(db, scan_engine_id: int, asset_id: int, status: str, error_message: str | None = None) -> None:
    """Upserts this engine's outcome for one target — shared by the
    external (in-process) engines and, conceptually, mirrored by the
    presence agent's own reporting over the API for internal scans."""
    from app.models import ScanEngineTarget

    row = db.query(ScanEngineTarget).filter_by(scan_engine_id=scan_engine_id, asset_id=asset_id).first()
    if not row:
        row = ScanEngineTarget(scan_engine_id=scan_engine_id, asset_id=asset_id, status=status)
        db.add(row)
    else:
        row.status = status
    row.error_message = error_message


def update_scan_status(scan_id: int, db) -> None:
    """Recompute Scan.status from all ScanEngine rows. Called by each engine
    runner when it finishes, so the overall status always reflects reality:
      - 'canceled'                       -> terminal, never overwritten
      - all queued                       -> queued
      - any running/queued                -> running
      - all finished (completed/failed/canceled) -> completed (or 'failed' if any engine failed)
    """
    from app.models import Scan, ScanEngine

    scan = db.get(Scan, scan_id)
    if not scan:
        return

    if scan.status == "canceled":
        return

    engines = db.query(ScanEngine).filter_by(scan_id=scan_id).all()
    if not engines:
        return

    statuses = {e.status for e in engines}
    terminal = {"completed", "failed", "canceled"}

    if statuses <= {"queued"}:
        scan.status = "queued"
    elif all(s in terminal for s in statuses):
        scan.status = "failed" if "failed" in statuses else "completed"
        if not scan.end_time:
            scan.end_time = utcnow()
    else:
        scan.status = "running"

    db.commit()
