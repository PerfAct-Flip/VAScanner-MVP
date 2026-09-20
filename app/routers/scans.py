from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models import Agent, Asset, Credential, Finding, Scan, ScanEngine, ScanTarget
from app.scanning.common import clear_cancel, request_cancel
from app.scanning.crypto import encrypt_secret
from app.scanning.orchestrator import ENGINES, execute_scan, retry_external_engines
from app.schemas import FindingOut, ScanCreate, ScanEngineStatusOut, ScanFindingsOut, ScanOut, ScanStatusOut

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=201)
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    assets = db.query(Asset).filter(Asset.id.in_(payload.asset_ids)).all()
    found_ids = {a.id for a in assets}
    missing = set(payload.asset_ids) - found_ids
    if missing:
        raise HTTPException(status_code=404, detail=f"Unknown asset_ids: {sorted(missing)}")

    if payload.type == "internal":
        agent = db.get(Agent, payload.agent_id)
        if not agent or agent.type != "internal":
            raise HTTPException(status_code=404, detail=f"Unknown internal agent_id: {payload.agent_id}")

    scan = Scan(
        type=payload.type,
        status="queued",
        requested_engines=",".join(payload.engines) if payload.engines is not None else None,
    )
    db.add(scan)
    db.flush()

    for asset_id in payload.asset_ids:
        db.add(ScanTarget(scan_id=scan.id, asset_id=asset_id))

    if payload.type == "external":
        selected = payload.engines if payload.engines is not None else list(ENGINES)
        for engine_name in selected:
            db.add(ScanEngine(scan_id=scan.id, engine=engine_name, status="queued", progress="Queued", progress_pct=0))
    else:
        # Default (engines=None) or "discover" explicitly selected: start
        # with just the discovery job pinned to the chosen agent; nuclei/
        # openvas jobs get queued once discovery reports back what's
        # actually alive on that network (see POST /agents/jobs/{id}/complete,
        # which re-reads Scan.requested_engines to decide what to queue).
        # "discover" explicitly excluded: skip straight to the selected
        # engines against whatever assets were pre-seeded (validated
        # non-empty by ScanCreate in that case).
        run_discover = payload.engines is None or "discover" in payload.engines
        if run_discover:
            db.add(
                ScanEngine(
                    scan_id=scan.id,
                    engine="discover",
                    status="queued",
                    progress="Queued",
                    progress_pct=0,
                    agent_id=payload.agent_id,
                )
            )
        else:
            for engine_name in payload.engines:
                db.add(
                    ScanEngine(
                        scan_id=scan.id,
                        engine=engine_name,
                        status="queued",
                        progress="Queued",
                        progress_pct=0,
                        agent_id=payload.agent_id,
                    )
                )
        for cred in payload.credentials:
            db.add(
                Credential(
                    scan_id=scan.id,
                    type=cred.type,
                    username=cred.username,
                    secret_encrypted=encrypt_secret(cred.secret),
                    port=cred.port,
                )
            )

    db.commit()
    db.refresh(scan)

    # External: Nuclei and OpenVAS run as independent parallel jobs right away.
    # Internal: this just flips the scan to 'running' — the agent does the work.
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
    engine_data: dict[str, ScanEngineStatusOut] = {}
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

    return ScanFindingsOut(
        scan_id=scan_id,
        nuclei=[FindingOut.model_validate(f) for f in nuclei],
        openvas=[FindingOut.model_validate(f) for f in openvas],
    )


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


@router.post("/{scan_id}/retry", response_model=ScanOut)
def retry_scan(scan_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = db.query(Scan).options(joinedload(Scan.engines)).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "failed":
        raise HTTPException(status_code=409, detail=f"Only failed scans can be retried (current status: '{scan.status}')")

    failed_engines = [se for se in scan.engines if se.status == "failed"]
    if not failed_engines:
        raise HTTPException(status_code=409, detail="No failed engines to retry")

    # Reset only the engines that actually failed — one already-completed
    # (e.g. Nuclei succeeded, only OpenVAS failed) is left untouched, so a
    # retry never redoes or duplicates work that already succeeded.
    retried_engine_names: set[str] = set()
    for se in failed_engines:
        se.status = "queued"
        se.progress = "Queued"
        se.progress_pct = 0
        se.error_message = None
        se.started_at = None
        se.finished_at = None
        se.claimed_at = None
        retried_engine_names.add(se.engine)

    clear_cancel(scan_id)
    scan.status = "running"
    scan.end_time = None
    db.commit()
    db.refresh(scan)

    if scan.type == "external":
        asset_ids = [st.asset_id for st in db.query(ScanTarget).filter_by(scan_id=scan_id).all()]
        background_tasks.add_task(retry_external_engines, scan_id, asset_ids, retried_engine_names)
    # Internal: nothing to trigger here — the engine(s) are now 'queued' again
    # and the pinned agent will pick them up on its next poll.

    return (
        db.query(Scan)
        .options(joinedload(Scan.engines))
        .filter(Scan.id == scan.id)
        .first()
    )
