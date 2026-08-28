import json
import shutil
import subprocess

from app.config import settings
from app.database import SessionLocal
from app.models import Asset, Finding, ScanEngine, normalize_severity
from app.scanning.common import is_cancelled, update_scan_status, utcnow, validate_target


_BINARY_VERIFIED = False


def _resolve_nuclei_binary() -> str:
    exe = shutil.which(settings.nuclei_binary) or shutil.which(f"{settings.nuclei_binary}.exe")
    return exe or settings.nuclei_binary


def _verify_nuclei_binary() -> None:
    """Run `nuclei -version` once with a bounded timeout before trusting the
    resolved binary for real scans. A package-manager shim pointing at a
    missing/corrupt target (seen with a broken scoop install) can hang or
    re-invoke itself indefinitely instead of failing fast — this catches
    that up front instead of discovering it mid-scan."""
    global _BINARY_VERIFIED
    if _BINARY_VERIFIED:
        return

    exe = _resolve_nuclei_binary()
    try:
        result = _run_with_tree_kill_on_timeout([exe, "-version"], timeout=20)
    except Exception as exc:
        raise Exception(f"nuclei binary '{exe}' failed a startup health check: {exc}") from exc

    if result.returncode != 0:
        raise Exception(f"nuclei binary '{exe}' -version exited {result.returncode}:\n{result.stdout[:500]}")

    _BINARY_VERIFIED = True


def _build_nuclei_cmd(target: str) -> list[str]:
    return [
        _resolve_nuclei_binary(),
        "-u", target,
        "-tags", settings.nuclei_tags,
        "-severity", settings.nuclei_severity,
        "-duc",  # disable nuclei's own update check — never let a scan stall on network I/O to GitHub
        "-j",
        "-silent",
    ]


def _kill_process_tree(pid: int) -> None:
    import os
    import platform

    if platform.system() == "Windows":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
    else:
        import signal

        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _run_with_tree_kill_on_timeout(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    import platform

    popen_kwargs = {}
    if platform.system() != "Windows":
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        **popen_kwargs,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc.pid)
        proc.wait()
        raise Exception(f"Nuclei scan timed out after {timeout}s and its process tree was killed.")
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout=stdout)


def _run_nuclei_scan(scan_id: int, asset_id: int, target: str, se: ScanEngine, db) -> None:
    se.progress = f"Running Nuclei on {target}..."
    se.progress_pct = 20
    db.commit()

    cmd = _build_nuclei_cmd(target)
    result = _run_with_tree_kill_on_timeout(cmd, timeout=settings.nuclei_timeout_seconds)
    if result.returncode not in (0, 1):
        # nuclei exits 1 on some template errors while still emitting valid results;
        # treat anything else as a hard failure.
        raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout[:2000]}")

    se.progress = f"Parsing Nuclei results for {target}..."
    se.progress_pct = 80
    db.commit()

    count = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        finding = Finding(
            scan_id=scan_id,
            asset_id=asset_id,
            engine="nuclei",
            severity=normalize_severity(info.get("severity")),
            cve=(info.get("classification") or {}).get("cve-id", ""),
            description=info.get("description") or info.get("name") or "Nuclei finding",
            recommendation=info.get("remediation", ""),
        )
        db.add(finding)
        count += 1

    db.commit()
    se.progress = f"Nuclei completed for {target} ({count} findings)."
    se.progress_pct = 95
    db.commit()


def run_nuclei_engine(scan_id: int, asset_ids: list[int]) -> None:
    """Runs Nuclei against all scan targets independently. All exceptions are
    caught and recorded on the ScanEngine row — never re-raised. A failure
    here never affects the OpenVAS engine."""
    db = SessionLocal()
    try:
        se = db.query(ScanEngine).filter_by(scan_id=scan_id, engine="nuclei").first()
        if not se:
            return

        se.status = "running"
        se.started_at = utcnow()
        se.progress = "Initializing Nuclei..."
        se.progress_pct = 5
        db.commit()

        final_status = "completed"
        try:
            _verify_nuclei_binary()

            for asset_id in asset_ids:
                if is_cancelled(scan_id):
                    final_status = "canceled"
                    break

                asset = db.get(Asset, asset_id)
                if not asset:
                    continue
                target = asset.hostname or asset.ip_address
                if not target:
                    continue

                validate_target(target)
                _run_nuclei_scan(scan_id, asset_id, target, se, db)

            if final_status == "completed":
                se.progress = "Nuclei scan completed"
                se.progress_pct = 100
            else:
                se.progress = "Canceled by user"
        except Exception as exc:  # noqa: BLE001 - deliberately broad, recorded not raised
            db.rollback()
            final_status = "failed"
            se.error_message = str(exc)
            se.progress = "Failed"
        finally:
            se.finished_at = utcnow()
            # Re-check current DB status: the cancel endpoint may have already
            # committed 'canceled' from another session while we were running.
            db.expire(se, ["status"])
            if se.status == "canceled":
                db.rollback()
            else:
                se.status = final_status
                db.commit()
            update_scan_status(scan_id, db)
    finally:
        db.close()
