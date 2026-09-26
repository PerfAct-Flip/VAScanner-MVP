import json
import shutil
import subprocess
from urllib.parse import urlparse

from app.config import settings
from app.database import SessionLocal
from app.models import Asset, Finding, ScanEngine, normalize_severity
from app.scanning.common import (
    already_succeeded_targets,
    is_cancelled,
    record_target_result,
    update_scan_status,
    utcnow,
    validate_target,
)
from app.scanning.errors import humanize_exception


_BINARY_VERIFIED = False


def _extract_port(data: dict) -> int | None:
    """See agent/presence_agent/nuclei_runner.py's copy of this — same
    reasoning, kept separate since this runs in a different process/package
    with no shared dependency between the two."""
    port = data.get("port")
    if port:
        try:
            return int(port)
        except (TypeError, ValueError):
            pass

    matched = data.get("matched-at") or data.get("host") or ""
    if not matched:
        return None
    parsed = urlparse(matched if "://" in matched else f"//{matched}")
    if parsed.port:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


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
        classification = info.get("classification") or {}
        finding = Finding(
            scan_id=scan_id,
            asset_id=asset_id,
            engine="nuclei",
            severity=normalize_severity(info.get("severity")),
            cve=classification.get("cve-id", ""),
            description=info.get("description") or info.get("name") or "Nuclei finding",
            recommendation=info.get("remediation", ""),
            cvss_score=classification.get("cvss-score"),
            port=_extract_port(data),
        )
        db.add(finding)
        count += 1

    db.commit()
    se.progress = f"Nuclei completed for {target} ({count} findings)."
    se.progress_pct = 95
    db.commit()


def run_nuclei_engine(scan_id: int, asset_ids: list[int]) -> None:
    """Runs Nuclei against all scan targets independently. One bad target
    (DNS failure, template error, timeout) is recorded and skipped, never
    aborting the rest — contrast with a startup/structural failure (e.g.
    the binary itself is missing), which still fails the whole engine since
    nothing can run at all. A retry only re-attempts targets that didn't
    already succeed (see already_succeeded_targets), so it never re-scans —
    or double-records findings for — an asset that already passed."""
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
        any_success = bool(already_succeeded_targets(db, se.id))
        last_error: str | None = None
        try:
            _verify_nuclei_binary()
            remaining = [aid for aid in asset_ids if aid not in already_succeeded_targets(db, se.id)]

            for i, asset_id in enumerate(remaining, start=1):
                if is_cancelled(scan_id):
                    final_status = "canceled"
                    break

                asset = db.get(Asset, asset_id)
                if not asset:
                    continue
                target = asset.hostname or asset.ip_address
                if not target:
                    continue

                se.progress = f"Scanning {target} ({i}/{len(remaining)})..."
                se.progress_pct = min(90, int(i / len(remaining) * 90))
                db.commit()

                try:
                    validate_target(target)
                    _run_nuclei_scan(scan_id, asset_id, target, se, db)
                except Exception as exc:
                    db.rollback()
                    last_error = humanize_exception(exc)
                    record_target_result(db, se.id, asset_id, "failed", last_error)
                    db.commit()
                    continue

                any_success = True
                record_target_result(db, se.id, asset_id, "succeeded")
                db.commit()

            if final_status == "completed":
                final_status = "completed" if (not asset_ids or any_success) else "failed"
                if final_status == "completed":
                    se.progress = "Nuclei scan completed"
                    se.progress_pct = 100
                else:
                    se.progress = "Failed"
                    se.error_message = last_error
            else:
                se.progress = "Canceled by user"
        except Exception as exc:  # noqa: BLE001 - deliberately broad: a structural failure, not a per-target one
            db.rollback()
            final_status = "failed"
            se.error_message = humanize_exception(exc)
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
