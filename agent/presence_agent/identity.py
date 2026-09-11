import json

from .client import BackendClient
from .config import Config


def load_or_register(cfg: Config, client: BackendClient) -> tuple[int, str]:
    """Loads a previously-issued (agent_id, api_key) pair from disk, or pairs
    with the backend for the first time and persists what it returns. The
    backend only ever shows the plaintext key once, at registration — so
    losing this file means registering under a new AGENT_NAME, not
    recovering the old identity."""
    if cfg.state_path.exists():
        data = json.loads(cfg.state_path.read_text())
        return data["agent_id"], data["api_key"]

    print(f"No stored identity at {cfg.state_path} — registering as '{cfg.agent_name}'...")
    agent_id, api_key = client.register(cfg.agent_name, cfg.agent_type)

    cfg.state_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.state_path.write_text(json.dumps({"agent_id": agent_id, "api_key": api_key}))
    cfg.state_path.chmod(0o600)

    print(f"Registered as agent_id={agent_id}. Credentials saved to {cfg.state_path} — back this file up.")
    return agent_id, api_key
