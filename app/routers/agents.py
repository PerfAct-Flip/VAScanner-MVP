from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent
from app.schemas import AgentHeartbeat, AgentOut
from app.scanning.common import utcnow

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])


@router.post("/heartbeat", response_model=AgentOut)
def agent_heartbeat(payload: AgentHeartbeat, db: Session = Depends(get_db)):
    agent = db.query(Agent).filter_by(name=payload.name).first()
    if not agent:
        agent = Agent(name=payload.name, type=payload.type, status="online")
        db.add(agent)
    else:
        agent.status = "online"
        agent.type = payload.type
        agent.last_seen = utcnow()
    db.commit()
    db.refresh(agent)
    return agent


@router.get("", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db)):
    return db.query(Agent).order_by(Agent.last_seen.desc()).all()
