import os
import time

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


def _wait_for_openvas_socket(se: ScanEngine, db) -> None:
    path = settings.openvas_socket_path
    if os.path.exists(path):
        pass
    else:
        waited = 0
        while not os.path.exists(path) and waited < settings.openvas_socket_wait_seconds:
            time.sleep(5)
            waited += 5
            se.progress = f"Waiting for OpenVAS socket ({waited}/{settings.openvas_socket_wait_seconds}s)..."
            db.commit()
        if not os.path.exists(path):
            raise Exception(f"OpenVAS socket missing at {path} after {settings.openvas_socket_wait_seconds}s.")

    if not os.access(path, os.R_OK | os.W_OK):
        raise Exception(f"Permission denied to OpenVAS socket {path}.")


def _get_port_list_id(gmp):
    res = gmp.get_port_lists(filter_string=f"name={settings.openvas_port_list_name}")
    ids = res.xpath("port_list/@id")
    if not ids:
        raise Exception(f"OpenVAS: could not find port list '{settings.openvas_port_list_name}'")
    return ids[0]


def _get_scan_config_id(gmp):
    res = gmp.get_scan_configs(filter_string=f"name={settings.openvas_scan_config_name}")
    ids = res.xpath("config/@id")
    if not ids:
        raise Exception(f"OpenVAS: could not find scan config '{settings.openvas_scan_config_name}'")
    return ids[0]


def _get_scanner_id(gmp):
    res = gmp.get_scanners(filter_string=f"name={settings.openvas_scanner_name}")
    ids = res.xpath("scanner/@id")
    if not ids:
        raise Exception(f"OpenVAS: could not find scanner '{settings.openvas_scanner_name}'")
    return ids[0]


def _poll_openvas_task(gmp, task_id: str, scan_id: int, se: ScanEngine, db) -> None:
    deadline = time.time() + settings.openvas_poll_timeout_seconds
    while True:
        if is_cancelled(scan_id):
            try:
                gmp.stop_task(task_id)
            except Exception:
                pass
            raise _Canceled()

        task = gmp.get_task(task_id)
        status = task.xpath("//status")[0].text

        progress_node = task.xpath("//progress")
        if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
            val = int(progress_node[0].text)
            if val > 0:
                se.progress_pct = min(99, max(20, val))
                db.commit()

        if status in ("Done", "Stopped"):
            return
        if status in ("Interrupted", "Failed", "Error"):
            raise Exception(f"OpenVAS task ended with status: {status}")
        if time.time() > deadline:
            raise Exception(f"OpenVAS task timed out after {settings.openvas_poll_timeout_seconds}s (status: {status}).")
        time.sleep(5)


def _save_openvas_results(results, scan_id: int, asset_id: int, db) -> int:
    count = 0
    for result in results.xpath("//result"):
        severity_node = result.find("threat")
        severity = normalize_severity(severity_node.text if severity_node is not None else "")

        desc_node = result.find("description")
        desc = desc_node.text if desc_node is not None else ""

        cve = ""
        cvss_score = None
        nvt = result.find("nvt")
        if nvt is not None:
            cve_node = nvt.find("cve")
            if cve_node is not None and cve_node.text and cve_node.text != "NOCVE":
                cve = cve_node.text
            cvss_node = nvt.find("cvss_base")
            if cvss_node is not None and cvss_node.text:
                try:
                    cvss_score = float(cvss_node.text)
                except ValueError:
                    pass

        port = None
        port_node = result.find("port")
        if port_node is not None and port_node.text:
            # GVM formats this like "443/tcp" or "general/tcp" (no port).
            head = port_node.text.split("/", 1)[0]
            if head.isdigit():
                port = int(head)

        finding = Finding(
            scan_id=scan_id,
            asset_id=asset_id,
            engine="openvas",
            severity=severity,
            cve=cve,
            description=(desc or "").strip(),
            recommendation="",
            cvss_score=cvss_score,
            port=port,
        )
        db.add(finding)
        count += 1
    return count


class _Canceled(Exception):
    pass


def _run_openvas_scan(scan_id: int, asset_id: int, target: str, se: ScanEngine, db) -> None:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform

    try:
        from gvm.protocols.gmp.requests.v224 import AliveTest
    except ImportError:
        AliveTest = None

    _wait_for_openvas_socket(se, db)

    connection = UnixSocketConnection(path=settings.openvas_socket_path)
    transform = EtreeTransform()

    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(settings.openvas_username, settings.openvas_password)

        port_list_id = _get_port_list_id(gmp)
        config_id = _get_scan_config_id(gmp)
        scanner_id = _get_scanner_id(gmp)

        se.progress = f"Creating OpenVAS target {target}..."
        se.progress_pct = 10
        db.commit()

        kwargs = dict(name=f"Target-{target}-{scan_id}-{asset_id}", hosts=[target], port_list_id=port_list_id)
        if AliveTest is not None:
            kwargs["alive_test"] = AliveTest.SCAN_CONFIG_DEFAULT

        res = gmp.create_target(**kwargs)
        if res.get("status") != "201":
            raise Exception(f"OpenVAS create_target failed: {res.get('status_text')}")
        target_id = res.xpath("//@id")[0]

        se.progress = "Creating OpenVAS task..."
        se.progress_pct = 15
        db.commit()

        res = gmp.create_task(
            name=f"Task-{target}-{scan_id}-{asset_id}",
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        if res.get("status") != "201":
            raise Exception(f"OpenVAS create_task failed: {res.get('status_text')}")
        task_id = res.xpath("//@id")[0]

        se.openvas_task_id = task_id
        db.commit()

        res = gmp.start_task(task_id)
        if res.get("status") != "202":
            raise Exception(f"OpenVAS start_task failed: {res.get('status_text')}")
        report_id = res.xpath("//report_id")[0].text

        se.progress = "Polling OpenVAS task..."
        se.progress_pct = 20
        db.commit()

        _poll_openvas_task(gmp, task_id, scan_id, se, db)

        se.progress = "Parsing OpenVAS results..."
        se.progress_pct = 99
        db.commit()

        results = gmp.get_results(filter_string=f"report_id={report_id}")
        report_xml = gmp.get_report(report_id)

        host_node = report_xml.xpath("//report/report/host")
        if not host_node and not results.xpath("//result"):
            raise Exception(f"OpenVAS: target '{target}' was considered dead or unreachable.")

        count = _save_openvas_results(results, scan_id, asset_id, db)
        db.commit()

        se.progress = f"OpenVAS completed for {target} ({count} findings)."
        se.progress_pct = 100
        db.commit()


def run_openvas_engine(scan_id: int, asset_ids: list[int]) -> None:
    """Runs OpenVAS against all scan targets independently. One bad target
    (DNS failure, GVM task error, target considered dead) is recorded and
    skipped, never aborting the rest — a full user-initiated cancel
    (_Canceled) is the one thing that still aborts everything. A retry only
    re-attempts targets that didn't already succeed (see
    already_succeeded_targets), so it never re-scans — or double-records
    findings for — an asset that already passed."""
    db = SessionLocal()
    try:
        se = db.query(ScanEngine).filter_by(scan_id=scan_id, engine="openvas").first()
        if not se:
            return

        se.status = "running"
        se.started_at = utcnow()
        se.progress = "Initializing OpenVAS..."
        se.progress_pct = 5
        db.commit()

        final_status = "completed"
        any_success = bool(already_succeeded_targets(db, se.id))
        last_error: str | None = None
        try:
            remaining = [aid for aid in asset_ids if aid not in already_succeeded_targets(db, se.id)]

            for asset_id in remaining:
                if is_cancelled(scan_id):
                    final_status = "canceled"
                    break

                asset = db.get(Asset, asset_id)
                if not asset:
                    continue
                target = asset.ip_address or asset.hostname
                if not target:
                    continue

                try:
                    validate_target(target)
                    _run_openvas_scan(scan_id, asset_id, target, se, db)
                except _Canceled:
                    raise
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
                    se.progress = "OpenVAS scan completed"
                    se.progress_pct = 100
                else:
                    se.progress = "Failed"
                    se.error_message = last_error
            else:
                se.progress = "Canceled by user"
        except _Canceled:
            db.rollback()
            final_status = "canceled"
            se.progress = "Canceled by user"
        except Exception as exc:  # noqa: BLE001 - deliberately broad: a structural failure, not a per-target one
            db.rollback()
            final_status = "failed"
            se.error_message = humanize_exception(exc)
            se.progress = "Failed"
        finally:
            se.finished_at = utcnow()
            db.expire(se, ["status"])
            if se.status == "canceled":
                db.rollback()
            else:
                se.status = final_status
                db.commit()
            update_scan_status(scan_id, db)
    finally:
        db.close()
