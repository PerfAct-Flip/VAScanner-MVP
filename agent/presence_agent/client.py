import requests


class BackendClient:
    def __init__(self, base_url: str, agent_id: int | None = None, api_key: str | None = None):
        self.base_url = base_url
        self.agent_id = agent_id
        self.api_key = api_key
        self.session = requests.Session()

    def _headers(self) -> dict:
        return {"X-Agent-Id": str(self.agent_id), "X-Agent-Key": self.api_key}

    def register(self, name: str, type_: str) -> tuple[int, str]:
        r = self.session.post(f"{self.base_url}/api/v1/agents/register", json={"name": name, "type": type_}, timeout=15)
        r.raise_for_status()
        data = r.json()
        return data["id"], data["api_key"]

    def heartbeat(self) -> None:
        r = self.session.post(f"{self.base_url}/api/v1/agents/heartbeat", headers=self._headers(), timeout=15)
        r.raise_for_status()

    def next_job(self) -> dict | None:
        r = self.session.get(f"{self.base_url}/api/v1/agents/jobs/next", headers=self._headers(), timeout=15)
        r.raise_for_status()
        return r.json()

    def progress(self, scan_engine_id: int, progress: str | None = None, progress_pct: int | None = None) -> bool:
        """Pushes a progress update and returns whether the backend has
        since marked this job canceled (a user hit cancel while we were
        mid-scan, on a machine with no shared memory to check directly)."""
        body = {}
        if progress is not None:
            body["progress"] = progress
        if progress_pct is not None:
            body["progress_pct"] = progress_pct
        r = self.session.post(
            f"{self.base_url}/api/v1/agents/jobs/{scan_engine_id}/progress", json=body, headers=self._headers(), timeout=15
        )
        r.raise_for_status()
        return bool(r.json().get("canceled", False))

    def submit_hosts(self, scan_engine_id: int, hosts: list[dict]) -> None:
        r = self.session.post(
            f"{self.base_url}/api/v1/agents/jobs/{scan_engine_id}/results",
            json={"hosts": hosts},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()

    def submit_findings(self, scan_engine_id: int, findings: list[dict]) -> None:
        r = self.session.post(
            f"{self.base_url}/api/v1/agents/jobs/{scan_engine_id}/results",
            json={"findings": findings},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()

    def submit_target_result(
        self, scan_engine_id: int, asset_id: int, status: str, error_message: str | None = None
    ) -> None:
        """Records whether this engine succeeded or failed against one
        specific target, so a later retry of this job can skip targets that
        already succeeded instead of re-attempting every target again."""
        r = self.session.post(
            f"{self.base_url}/api/v1/agents/jobs/{scan_engine_id}/results",
            json={"target_results": [{"asset_id": asset_id, "status": status, "error_message": error_message}]},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()

    def complete(self, scan_engine_id: int, status: str, error_message: str | None = None) -> None:
        r = self.session.post(
            f"{self.base_url}/api/v1/agents/jobs/{scan_engine_id}/complete",
            json={"status": status, "error_message": error_message},
            headers=self._headers(),
            timeout=15,
        )
        r.raise_for_status()
