import re

import paramiko


def _try_exec(client: paramiko.SSHClient, command: str, timeout: int) -> str | None:
    """Best-effort command execution — many targets (embedded routers running
    BusyBox/dropbear especially) won't support every command here. A failure
    just means that particular check is skipped, not that the audit fails."""
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace").strip()
    except Exception:
        return None


def audit_host(host: str, username: str, secret: str, port: int | None, timeout: int) -> list[dict]:
    """Connects over SSH with a password and runs a small, fixed set of
    read-only checks. This is a lightweight purpose-built auditor, not a
    replacement for a real vulnerability scanner (OpenVAS/GVM) — it checks
    a handful of concrete, high-signal misconfigurations rather than
    matching against a CVE database."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port or 22,
        username=username,
        password=secret,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
    )

    findings: list[dict] = []
    try:
        sshd_config = _try_exec(client, "cat /etc/ssh/sshd_config 2>/dev/null", timeout) or ""

        if re.search(r"^\s*PermitRootLogin\s+yes", sshd_config, re.MULTILINE):
            findings.append(
                {
                    "severity": "high",
                    "cve": None,
                    "description": "SSH is configured to permit root login (PermitRootLogin yes).",
                    "recommendation": "Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config and use a non-root account with sudo instead.",
                }
            )

        if re.search(r"^\s*PasswordAuthentication\s+yes", sshd_config, re.MULTILINE):
            findings.append(
                {
                    "severity": "medium",
                    "cve": None,
                    "description": "SSH permits password authentication, which is vulnerable to brute-force/credential-stuffing attacks.",
                    "recommendation": "Disable password authentication ('PasswordAuthentication no') and require SSH key-based auth instead.",
                }
            )

        upgradable = _try_exec(client, "apt list --upgradable 2>/dev/null | tail -n +2", timeout)
        if upgradable is None:
            upgradable = _try_exec(client, "dnf check-update 2>/dev/null | tail -n +3", timeout) or _try_exec(
                client, "yum check-update 2>/dev/null | tail -n +3", timeout
            )
        if upgradable:
            count = len([line for line in upgradable.splitlines() if line.strip()])
            if count > 0:
                findings.append(
                    {
                        "severity": "medium",
                        "cve": None,
                        "description": f"{count} package(s) have available updates (patch level not current).",
                        "recommendation": "Apply pending OS/package updates (apt upgrade / dnf upgrade).",
                    }
                )

        banner = _try_exec(client, "uname -a", timeout) or _try_exec(client, "cat /proc/version", timeout)
        if banner:
            findings.append(
                {
                    "severity": "informational",
                    "cve": None,
                    "description": f"Authenticated SSH audit connected successfully. System: {banner}",
                    "recommendation": None,
                }
            )
    finally:
        client.close()

    return findings
