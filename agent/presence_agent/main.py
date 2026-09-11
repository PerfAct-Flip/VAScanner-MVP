import time
import traceback

from . import discovery, nuclei_runner
from .client import BackendClient
from .config import Config
from .identity import load_or_register


def handle_discover(client: BackendClient, cfg: Config, job: dict) -> None:
    se_id = job["scan_engine_id"]
    subnets = discovery.local_subnets()
    if not subnets:
        client.complete(se_id, status="failed", error_message="No active non-loopback IPv4 interfaces to scan.")
        return

    client.progress(se_id, progress=f"Scanning {', '.join(subnets)}...", progress_pct=20)
    hosts = discovery.discover_hosts(cfg.nmap_binary, subnets, cfg.discovery_timeout_seconds)
    client.progress(se_id, progress=f"Found {len(hosts)} live host(s)", progress_pct=80)
    client.submit_hosts(se_id, hosts)
    client.complete(se_id, status="completed")


def handle_nuclei(client: BackendClient, cfg: Config, job: dict) -> None:
    se_id = job["scan_engine_id"]
    targets = job.get("targets", [])
    nuclei_runner.verify_nuclei_binary(cfg.nuclei_binary)

    total = len(targets) or 1
    for i, t in enumerate(targets, start=1):
        target = t.get("hostname") or t.get("ip_address")
        if not target:
            continue

        canceled = client.progress(se_id, progress=f"Scanning {target} ({i}/{len(targets)})", progress_pct=int(i / total * 90))
        if canceled:
            return  # backend already marked this job canceled; stop working on it

        findings = nuclei_runner.scan_target(cfg.nuclei_binary, cfg.nuclei_tags, cfg.nuclei_severity, target, cfg.nuclei_timeout_seconds)
        if findings:
            client.submit_findings(se_id, [{**f, "asset_id": t["asset_id"]} for f in findings])

    client.complete(se_id, status="completed")


def handle_openvas(client: BackendClient, cfg: Config, job: dict) -> None:
    client.complete(job["scan_engine_id"], status="failed", error_message="OpenVAS is not yet implemented on this agent.")


HANDLERS = {"discover": handle_discover, "nuclei": handle_nuclei, "openvas": handle_openvas}


def run(cfg: Config) -> None:
    client = BackendClient(cfg.backend_url)
    agent_id, api_key = load_or_register(cfg, client)
    client.agent_id, client.api_key = agent_id, api_key

    print(f"Presence Agent running as agent_id={agent_id}, polling {cfg.backend_url}")
    last_heartbeat = 0.0
    while True:
        now = time.time()
        if now - last_heartbeat >= cfg.heartbeat_interval_seconds:
            try:
                client.heartbeat()
            except Exception as exc:
                print(f"heartbeat failed: {exc}")
            last_heartbeat = now

        try:
            job = client.next_job()
        except Exception as exc:
            print(f"poll failed: {exc}")
            time.sleep(cfg.poll_interval_seconds)
            continue

        if not job:
            time.sleep(cfg.poll_interval_seconds)
            continue

        se_id, engine = job["scan_engine_id"], job["engine"]
        print(f"Claimed job {se_id} ({engine}) for scan {job['scan_id']}")
        handler = HANDLERS.get(engine)
        try:
            if handler:
                handler(client, cfg, job)
            else:
                client.complete(se_id, status="failed", error_message=f"Unknown engine '{engine}'")
        except Exception as exc:
            traceback.print_exc()
            try:
                client.complete(se_id, status="failed", error_message=str(exc)[:2000])
            except Exception:
                pass


def main() -> None:
    from dotenv import load_dotenv

    load_dotenv()
    run(Config.from_env())


if __name__ == "__main__":
    main()
