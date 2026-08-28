from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding
from app.schemas import EngineName, FindingOut

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: int | None = None,
    asset_id: int | None = None,
    engine: EngineName | None = None,
    severity: str | None = Query(default=None, description="Critical, High, Medium, Low, Informational"),
    db: Session = Depends(get_db),
):
    query = db.query(Finding)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    if engine is not None:
        query = query.filter(Finding.engine == engine)
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    return query.order_by(Finding.created_at.desc()).all()
