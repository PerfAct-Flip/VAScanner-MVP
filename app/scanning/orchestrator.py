import asyncio

from app.database import SessionLocal
from app.models import Scan, ScanEngine
from app.scanning.common import clear_cancel, utcnow
from app.scanning.nuclei import run_nuclei_engine
from app.scanning.openvas import run_openvas_engine

ENGINES = ("nuclei", "openvas")


async def execute_scan(scan_id: int, asset_ids: list[int]) -> None:
    """Creates one ScanEngine row per engine, then launches Nuclei and OpenVAS
    as independent, non-blocking parallel jobs against the same targets.
    Neither engine's failure or delay affects the other."""
    clear_cancel(scan_id)

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "running"
        scan.start_time = utcnow()

        for engine_name in ENGINES:
            existing = db.query(ScanEngine).filter_by(scan_id=scan_id, engine=engine_name).first()
            if not existing:
                db.add(ScanEngine(scan_id=scan_id, engine=engine_name, status="queued", progress="Queued", progress_pct=0))
        db.commit()
    finally:
        db.close()

    # Each runner opens its own DB session and thread; a blocking call (subprocess,
    # GVM socket I/O) in one never delays the other.
    await asyncio.gather(
        asyncio.to_thread(run_nuclei_engine, scan_id, asset_ids),
        asyncio.to_thread(run_openvas_engine, scan_id, asset_ids),
        return_exceptions=True,
    )
