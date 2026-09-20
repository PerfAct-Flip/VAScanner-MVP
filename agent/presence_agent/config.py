import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_PATH = Path.home() / ".presence-agent" / "credentials.json"


@dataclass
class Config:
    backend_url: str
    agent_name: str
    agent_type: str
    poll_interval_seconds: float
    heartbeat_interval_seconds: float
    nmap_binary: str
    discovery_timeout_seconds: int
    discovery_passes: int
    discovery_retry_delay_seconds: int
    discovery_top_ports: int
    nuclei_binary: str
    nuclei_tags: str
    nuclei_severity: str
    nuclei_timeout_seconds: int
    ssh_audit_timeout_seconds: int
    state_path: Path

    @classmethod
    def from_env(cls) -> "Config":
        backend_url = os.environ.get("BACKEND_URL")
        agent_name = os.environ.get("AGENT_NAME")
        if not backend_url or not agent_name:
            raise SystemExit("BACKEND_URL and AGENT_NAME must be set — see .env.example.")

        state_path = os.environ.get("STATE_PATH")
        return cls(
            backend_url=backend_url.rstrip("/"),
            agent_name=agent_name,
            agent_type=os.environ.get("AGENT_TYPE", "internal"),
            poll_interval_seconds=float(os.environ.get("POLL_INTERVAL_SECONDS", 5)),
            heartbeat_interval_seconds=float(os.environ.get("HEARTBEAT_INTERVAL_SECONDS", 60)),
            nmap_binary=os.environ.get("NMAP_BINARY", "nmap"),
            discovery_timeout_seconds=int(os.environ.get("DISCOVERY_TIMEOUT_SECONDS", 120)),
            discovery_passes=int(os.environ.get("DISCOVERY_PASSES", 2)),
            discovery_retry_delay_seconds=int(os.environ.get("DISCOVERY_RETRY_DELAY_SECONDS", 15)),
            discovery_top_ports=int(os.environ.get("DISCOVERY_TOP_PORTS", 50)),
            nuclei_binary=os.environ.get("NUCLEI_BINARY", "nuclei"),
            nuclei_tags=os.environ.get("NUCLEI_TAGS", "cve,misconfig"),
            nuclei_severity=os.environ.get("NUCLEI_SEVERITY", "critical,high,medium,low"),
            nuclei_timeout_seconds=int(os.environ.get("NUCLEI_TIMEOUT_SECONDS", 600)),
            ssh_audit_timeout_seconds=int(os.environ.get("SSH_AUDIT_TIMEOUT_SECONDS", 20)),
            state_path=Path(state_path).expanduser() if state_path else DEFAULT_STATE_PATH,
        )
