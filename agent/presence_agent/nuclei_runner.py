import json
import shutil
import subprocess
from urllib.parse import urlparse

from .retry import TransientError


def _extract_port(data: dict) -> int | None:
    """Nuclei's JSON output doesn't have one consistent field for this —
    check the explicit 'port' field first (some protocol templates set it),
    then fall back to parsing whatever host:port nuclei actually matched
    against, which is more accurate than assuming the target's default
    port when a template probes something else."""
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


def _resolve_nuclei_binary(nuclei_binary: str) -> str:
    return shutil.which(nuclei_binary) or shutil.which(f"{nuclei_binary}.exe") or nuclei_binary


def verify_nuclei_binary(nuclei_binary: str) -> None:
    exe = _resolve_nuclei_binary(nuclei_binary)
    try:
        result = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=20)
    except Exception as exc:
        raise Exception(f"nuclei binary '{exe}' failed a startup health check: {exc}") from exc
    if result.returncode != 0:
        raise Exception(f"nuclei binary '{exe}' -version exited {result.returncode}:\n{result.stdout[:500]}")


def scan_target(nuclei_binary: str, tags: str, severity: str, target: str, timeout: int) -> list[dict]:
    exe = _resolve_nuclei_binary(nuclei_binary)
    cmd = [exe, "-u", target, "-tags", tags, "-severity", severity, "-duc", "-j", "-silent"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        # Could be a genuinely slow/unresponsive target, or could be a
        # one-off network blip — worth a retry rather than an immediate
        # permanent failure.
        raise TransientError(f"Nuclei scan of {target} timed out after {timeout}s.") from exc

    if result.returncode not in (0, 1):
        # nuclei exits 1 on some template errors while still emitting valid results.
        raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout[:2000]}")

    findings = []
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
        findings.append(
            {
                "severity": info.get("severity"),
                "cve": classification.get("cve-id") or None,
                "description": info.get("description") or info.get("name") or "Nuclei finding",
                "recommendation": info.get("remediation") or None,
                "cvss_score": classification.get("cvss-score"),
                "port": _extract_port(data),
            }
        )
    return findings
