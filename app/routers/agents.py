import hashlib
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent, Asset, Credential, Finding, ScanEngine, ScanTarget, normalize_severity
from app.scanning.common import update_scan_status, utcnow
from app.scanning.crypto import decrypt_secret
from app.schemas import (
    AgentOut,
    AgentRegisterIn,
    AgentRegisterOut,
    JobCompleteIn,
    JobCredentialOut,
    JobOut,
    JobProgressIn,
    JobResultsIn,
    JobTargetOut,
)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def get_current_agent(
    x_agent_id: int = Header(...),
    x_agent_key: str = Header(...),
    db: Session = Depends(get_db),
) -> Agent:
    agent = db.get(Agent, x_agent_id)
    if not agent or not agent.api_key_hash or _hash_key(x_agent_key) != agent.api_key_hash:
        raise HTTPException(status_code=401, detail="Invalid agent credentials")
    agent.status = "online"
    agent.last_seen = utcnow()
    db.commit()
    return agent


def _owned_job(scan_engine_id: int, agent: Agent, db: Session) -> ScanEngine:
    se = db.get(ScanEngine, scan_engine_id)
    if not se:
        raise HTTPException(status_code=404, detail="Job not found")
    if se.agent_id != agent.id:
        raise HTTPException(status_code=403, detail="Job not assigned to this agent")
    return se


@router.post("/register", response_model=AgentRegisterOut, status_code=201)
def register_agent(payload: AgentRegisterIn, db: Session = Depends(get_db)):
    """One-time pairing: hands back a plaintext api_key that is never shown
    again and never stored — only its SHA-256 hash is. Re-registering a name
    that already has a key is refused; that key must be used as-is."""
    agent = db.query(Agent).filter_by(name=payload.name).first()
    if agent and agent.api_key_hash:
        raise HTTPException(status_code=409, detail="Agent already registered; use its existing key.")

    api_key = secrets.token_urlsafe(32)
    if agent:
        agent.type = payload.type
        agent.api_key_hash = _hash_key(api_key)
    else:
        agent = Agent(name=payload.name, type=payload.type, status="online", api_key_hash=_hash_key(api_key))
        db.add(agent)
    db.commit()
    db.refresh(agent)
    return AgentRegisterOut(
        id=agent.id, name=agent.name, type=agent.type, status=agent.status, last_seen=agent.last_seen, api_key=api_key
    )


@router.post("/heartbeat", response_model=AgentOut)
def agent_heartbeat(agent: Agent = Depends(get_current_agent)):
    return agent


@router.get("", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db)):
    return db.query(Agent).order_by(Agent.last_seen.desc()).all()


# ---------------------------------------------------------------------------
# Job queue — an internal scan's discover/nuclei/openvas ScanEngine rows are
# pinned to one target agent (set at scan-creation time), so an agent only
# ever sees jobs assigned to itself.
# ---------------------------------------------------------------------------


def _build_job_out(se: ScanEngine, db: Session) -> JobOut:
    targets: list[JobTargetOut] = []
    if se.engine != "discover":
        rows = (
            db.query(ScanTarget, Asset)
            .join(Asset, ScanTarget.asset_id == Asset.id)
            .filter(ScanTarget.scan_id == se.scan_id)
            .all()
        )
        targets = [
            JobTargetOut(asset_id=asset.id, hostname=asset.hostname, ip_address=asset.ip_address)
            for _, asset in rows
        ]

    credentials: list[JobCredentialOut] = []
    if se.engine == "openvas":
        creds = db.query(Credential).filter_by(scan_id=se.scan_id).all()
        credentials = [
            JobCredentialOut(type=c.type, username=c.username, secret=decrypt_secret(c.secret_encrypted), port=c.port)
            for c in creds
        ]

    return JobOut(scan_engine_id=se.id, scan_id=se.scan_id, engine=se.engine, targets=targets, credentials=credentials)


@router.get("/jobs/next", response_model=JobOut | None)
def next_job(agent: Agent = Depends(get_current_agent), db: Session = Depends(get_db)):
    candidate = (
        db.query(ScanEngine)
        .filter(ScanEngine.agent_id == agent.id, ScanEngine.status == "queued")
        .order_by(ScanEngine.id)
        .first()
    )
    if not candidate:
        return None

    now = utcnow()
    result = db.execute(
        update(ScanEngine)
        .where(ScanEngine.id == candidate.id, ScanEngine.status == "queued")
        .values(status="running", claimed_at=now, started_at=now, progress="Claimed by agent")
    )
    db.commit()
    if result.rowcount == 0:
        # Lost a race against another poll from the same agent; try again next poll.
        return None

    db.refresh(candidate)
    return _build_job_out(candidate, db)


@router.post("/jobs/{scan_engine_id}/progress")
def job_progress(
    scan_engine_id: int,
    payload: JobProgressIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    se = _owned_job(scan_engine_id, agent, db)
    if payload.progress is not None:
        se.progress = payload.progress
    if payload.progress_pct is not None:
        se.progress_pct = payload.progress_pct
    db.commit()
    # Lets the agent notice a user-initiated cancel (POST /scans/{id}/cancel
    # sets this same status field) despite running on a separate machine with
    # no shared memory to check.
    return {"canceled": se.status == "canceled"}


@router.post("/jobs/{scan_engine_id}/results")
def job_results(
    scan_engine_id: int,
    payload: JobResultsIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    se = _owned_job(scan_engine_id, agent, db)

    if se.engine == "discover":
        for host in payload.hosts or []:
            asset = db.query(Asset).filter_by(ip_address=host.ip_address).first()
            if not asset:
                asset = Asset(ip_address=host.ip_address, hostname=host.hostname)
                db.add(asset)
                db.flush()
            exists = db.query(ScanTarget).filter_by(scan_id=se.scan_id, asset_id=asset.id).first()
            if not exists:
                db.add(ScanTarget(scan_id=se.scan_id, asset_id=asset.id))
    else:
        valid_asset_ids = {st.asset_id for st in db.query(ScanTarget).filter_by(scan_id=se.scan_id).all()}
        for f in payload.findings or []:
            if f.asset_id not in valid_asset_ids:
                continue
            db.add(
                Finding(
                    scan_id=se.scan_id,
                    asset_id=f.asset_id,
                    engine=se.engine,
                    severity=normalize_severity(f.severity),
                    cve=f.cve,
                    description=f.description,
                    recommendation=f.recommendation,
                )
            )

    db.commit()
    return {"ok": True}


@router.post("/jobs/{scan_engine_id}/complete")
def job_complete(
    scan_engine_id: int,
    payload: JobCompleteIn,
    agent: Agent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    se = _owned_job(scan_engine_id, agent, db)
    se.status = payload.status
    se.error_message = payload.error_message
    se.finished_at = utcnow()
    if se.status == "completed":
        se.progress_pct = 100
    db.commit()

    # Discovery is only step one: once it lands, queue the actual scanning
    # engines against whatever it found (plus any pre-seeded assets), pinned
    # to the same agent that just ran discovery.
    if se.engine == "discover" and se.status == "completed":
        for engine_name in ("nuclei", "openvas"):
            db.add(
                ScanEngine(
                    scan_id=se.scan_id,
                    engine=engine_name,
                    status="queued",
                    progress="Queued",
                    progress_pct=0,
                    agent_id=se.agent_id,
                )
            )
        db.commit()

    update_scan_status(se.scan_id, db)
    return {"ok": True}
