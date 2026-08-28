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


def validate_target(target: str) -> None:
    """Raise if target is unresolvable. Shared by both engines."""
    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise Exception(f"Target '{target}' is unresolvable via DNS. Scan aborted.") from exc


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
