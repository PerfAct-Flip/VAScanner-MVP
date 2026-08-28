from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import Base, engine
from app.routers import agents, assets, findings, reports, scans


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Vendor Vulnerability Scanner API",
    description="Backend for vendors to scan internal/external assets with Nuclei and OpenVAS running in parallel per scan.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(agents.router)
