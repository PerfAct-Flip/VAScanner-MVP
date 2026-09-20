import time
import traceback

from . import discovery, nuclei_runner, ssh_audit
from .client import BackendClient
from .config import Config
from .identity import load_or_register
from .retry import with_retry


def handle_discover(client: BackendClient, cfg: Config, job: dict) -> None:
    se_id = job["scan_engine_id"]
    subnets = discovery.local_subnets()
    if not subnets:
        client.complete(se_id, status="failed", error_message="No active non-loopback IPv4 interfaces to scan.")
        return

    client.progress(se_id, progress=f"Scanning {', '.join(subnets)}...", progress_pct=20)
    hosts = discovery.discover_hosts(
        cfg.nmap_binary,
        subnets,
        cfg.discovery_timeout_seconds,
        passes=cfg.discovery_passes,
        retry_delay_seconds=cfg.discovery_retry_delay_seconds,
        top_ports=cfg.discovery_top_ports,
    )
    client.progress(se_id, progress=f"Found {len(hosts)} live host(s)", progress_pct=80)
    client.submit_hosts(se_id, hosts)
    client.complete(se_id, status="completed")


def handle_nuclei(client: BackendClient, cfg: Config, job: dict) -> None:
    se_id = job["scan_engine_id"]
    targets = job.get("targets", [])
    nuclei_runner.verify_nuclei_binary(cfg.nuclei_binary)

    total = len(targets) or 1
    any_success = False
    last_error: str | None = None
    for i, t in enumerate(targets, start=1):
        target = t.get("hostname") or t.get("ip_address")
        if not target:
            continue

        canceled = client.progress(se_id, progress=f"Scanning {target} ({i}/{len(targets)})", progress_pct=int(i / total * 90))
        if canceled:
            return  # backend already marked this job canceled; stop working on it

        try:
            findings = with_retry(
                lambda: nuclei_runner.scan_target(
                    cfg.nuclei_binary, cfg.nuclei_tags, cfg.nuclei_severity, target, cfg.nuclei_timeout_seconds
                )
            )
        except Exception as exc:
            # One unreachable/flaky target shouldn't sink the scan for
            # every other target in the job.
            last_error = f"{target}: {exc}"
            client.submit_target_result(se_id, t["asset_id"], status="failed", error_message=str(exc)[:2000])
            continue

        any_success = True
        client.submit_target_result(se_id, t["asset_id"], status="succeeded")
        if findings:
            client.submit_findings(se_id, [{**f, "asset_id": t["asset_id"]} for f in findings])

    if not targets or any_success:
        client.complete(se_id, status="completed")
    else:
        client.complete(se_id, status="failed", error_message=f"Nuclei failed against every target. Last error: {last_error}")


def handle_openvas(client: BackendClient, cfg: Config, job: dict) -> None:
    """Real OpenVAS/GVM would need its own scanner engine running with
    network access to the targets — the same reachability problem this
    whole agent exists to solve, which would mean deploying a full GVM
    stack on every customer site. Instead: a lightweight authenticated SSH
    audit using whatever SSH credentials the scan was given (see
    ssh_audit.py) — not a CVE-database scanner, but real credentialed
    checks (weak sshd config, pending package updates) against real hosts."""
    se_id = job["scan_engine_id"]
    ssh_creds = [c for c in job.get("credentials", []) if c.get("type") == "ssh"]
    targets = job.get("targets", [])

    if not ssh_creds:
        client.complete(
            se_id,
            status="failed",
            error_message="No SSH credentials provided. (Full OpenVAS/GVM scanning is not implemented on this "
            "agent — this engine performs a lightweight authenticated SSH audit instead, which needs "
            "at least one SSH credential attached to the scan.)",
        )
        return

    total = (len(targets) * len(ssh_creds)) or 1
    attempt = 0
    any_success = False
    last_error: str | None = None

    for t in targets:
        host = t.get("ip_address") or t.get("hostname")
        if not host:
            continue
        target_succeeded = False
        target_last_error: str | None = None
        for cred in ssh_creds:
            attempt += 1
            canceled = client.progress(
                se_id, progress=f"SSH audit: trying {host} ({attempt}/{total})", progress_pct=int(attempt / total * 90)
            )
            if canceled:
                return

            try:
                findings = with_retry(
                    lambda: ssh_audit.audit_host(
                        host, cred["username"], cred["secret"], cred.get("port"), cfg.ssh_audit_timeout_seconds
                    )
                )
            except Exception as exc:
                target_last_error = f"{host}: {exc}"
                continue  # this credential just didn't work for this host — try the next one, not fatal

            target_succeeded = True
            if findings:
                client.submit_findings(se_id, [{**f, "asset_id": t["asset_id"]} for f in findings])
            break  # this credential worked; no need to try the rest against this target

        client.submit_target_result(
            se_id,
            t["asset_id"],
            status="succeeded" if target_succeeded else "failed",
            error_message=None if target_succeeded else target_last_error,
        )
        if target_succeeded:
            any_success = True
        else:
            last_error = target_last_error

    if any_success:
        client.complete(se_id, status="completed")
    else:
        client.complete(
            se_id,
            status="failed",
            error_message=f"Could not authenticate via SSH to any target with the provided credential(s). Last error: {last_error}",
        )


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
