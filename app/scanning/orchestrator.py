import asyncio

from app.database import SessionLocal
from app.models import Scan, ScanEngine
from app.scanning.common import clear_cancel, utcnow
from app.scanning.nuclei import run_nuclei_engine
from app.scanning.openvas import run_openvas_engine

ENGINES = ("nuclei", "openvas")


async def execute_scan(scan_id: int, asset_ids: list[int]) -> None:
    """External scans: launches a runner for each ScanEngine row that
    already exists (created at scan-creation time per the user's engine
    selection — see POST /api/v1/scans) as an independent, non-blocking
    parallel job against the same targets, in-process on the backend.
    Neither engine's failure or delay affects the other, and an engine the
    user didn't select simply has no row and never runs.

    Internal scans run nothing here — their ScanEngine rows are created at
    scan-creation time already pinned to a target Presence Agent, which
    claims and executes them itself via GET /api/v1/agents/jobs/next. This
    function only needs to flip the scan to 'running' for them."""
    clear_cancel(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "running"
        scan.start_time = utcnow()
        db.commit()
        scan_type = scan.type
        engine_names = {e.engine for e in db.query(ScanEngine).filter_by(scan_id=scan_id).all()}
    finally:
        db.close()

    if scan_type != "external":
        return

    # Each runner opens its own DB session and thread; a blocking call (subprocess,
    # GVM socket I/O) in one never delays the other.
    tasks = []
    if "nuclei" in engine_names:
        tasks.append(asyncio.to_thread(run_nuclei_engine, scan_id, asset_ids))
    if "openvas" in engine_names:
        tasks.append(asyncio.to_thread(run_openvas_engine, scan_id, asset_ids))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def retry_external_engines(scan_id: int, asset_ids: list[int], engines: set[str]) -> None:
    """Re-runs only the given (previously failed, already reset to 'queued')
    engines for an external scan. Engines not in this set are left alone, so
    retrying one failed engine never redoes another that already succeeded."""
    clear_cancel(scan_id)

    tasks = []
    if "nuclei" in engines:
        tasks.append(asyncio.to_thread(run_nuclei_engine, scan_id, asset_ids))
    if "openvas" in engines:
        tasks.append(asyncio.to_thread(run_openvas_engine, scan_id, asset_ids))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
