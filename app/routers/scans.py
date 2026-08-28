from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import Asset, Finding, Scan, ScanEngine, ScanTarget
from app.scanning.common import request_cancel
from app.scanning.orchestrator import ENGINES, execute_scan
from app.schemas import ScanCreate, ScanEngineStatusOut, ScanFindingsOut, ScanOut, ScanStatusOut

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.id.in_(payload.asset_ids)).all()
    found_ids = {a.id for a in assets}
    missing = set(payload.asset_ids) - found_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown asset_ids: {sorted(missing)}")

    scan = Scan(type=payload.type, status="queued")
    db.add(scan)
    db.flush()

    for asset_id in payload.asset_ids:
        db.add(ScanTarget(scan_id=scan.id, asset_id=asset_id))

    for engine_name in ENGINES:
        db.add(ScanEngine(scan_id=scan.id, engine=engine_name, status="queued", progress="Queued", progress_pct=0))

    db.commit()
    db.refresh(scan)

    # Nuclei and OpenVAS run as independent parallel jobs; the request returns
    # immediately, poll GET /scans/{id}/status for live per-engine progress.
    background_tasks.add_task(execute_scan, scan.id, list(found_ids))

    return (
        db.query(Scan)
        .options(joinedload(Scan.engines))
        .filter(Scan.id == scan.id)
        .first()
    )


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).options(joinedload(Scan.engines)).order_by(Scan.created_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(joinedload(Scan.engines)).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/status", response_model=ScanStatusOut)
def scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    engines = db.query(ScanEngine).filter_by(scan_id=scan_id).all()
    engine_data = {}
    for se in engines:
        findings_count = db.query(Finding).filter_by(scan_id=scan_id, engine=se.engine).count()
        engine_data[se.engine] = ScanEngineStatusOut(
            status=se.status,
            progress=se.progress or "",
            progress_pct=se.progress_pct or 0,
            error_message=se.error_message,
            findings_count=findings_count,
            started_at=se.started_at.isoformat() if se.started_at else None,
            finished_at=se.finished_at.isoformat() if se.finished_at else None,
        )

    return ScanStatusOut(scan_id=scan_id, overall_status=scan.status, engines=engine_data)


@router.get("/{scan_id}/findings", response_model=ScanFindingsOut)
def scan_findings(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    nuclei = db.query(Finding).filter_by(scan_id=scan_id, engine="nuclei").order_by(Finding.created_at.desc()).all()
    openvas = db.query(Finding).filter_by(scan_id=scan_id, engine="openvas").order_by(Finding.created_at.desc()).all()

    return ScanFindingsOut(scan_id=scan_id, nuclei=nuclei, openvas=openvas)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(joinedload(Scan.engines)).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(status_code=409, detail=f"Scan cannot be canceled in status '{scan.status}'")

    # Cooperative cancel: engine runners check this flag between targets/polls
    # and will stop and mark themselves 'canceled' rather than being force-killed.
    request_cancel(scan_id)

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    for se in scan.engines:
        if se.status in ("queued", "running"):
            se.status = "canceled"
            se.progress = "Canceled by user"
            se.finished_at = now

    scan.status = "canceled"
    scan.end_time = now
    db.commit()
    db.refresh(scan)
    return scan
