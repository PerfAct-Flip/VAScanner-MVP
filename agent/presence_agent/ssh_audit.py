import re

import paramiko

from .errors import humanize_exception
from .retry import TransientError

_WEAK_CIPHERS = ("arcfour", "cbc", "3des", "blowfish", "des")
_WEAK_MACS = ("hmac-md5", "hmac-sha1", "hmac-sha1-96", "hmac-md5-96")
_WEAK_KEX = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")


def _try_exec(client: paramiko.SSHClient, command: str, timeout: int) -> str | None:
    """Best-effort command execution — many targets (embedded routers running
    BusyBox/dropbear especially) won't support every command here, and most
    checks below only work if this account happens to have sudo. A failure
    or permission denial just means that particular check is skipped, not
    that the audit fails."""
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode(errors="replace").strip()
    except Exception:
        return None


def _parse_effective_sshd_config(text: str) -> dict[str, str]:
    """Parses `sshd -T` output — one 'key value' pair per line, lowercase
    keys — into a dict. This is the fully *resolved* config (compiled-in
    defaults included), unlike grepping sshd_config directly, which misses
    anything not explicitly set there."""
    config: dict[str, str] = {}
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1]
    return config


def audit_host(host: str, username: str, secret: str, port: int | None, timeout: int) -> list[dict]:
    """Connects over SSH with a password and runs a small, fixed set of
    read-only checks. This is a lightweight purpose-built auditor, not a
    replacement for a real vulnerability scanner (OpenVAS/GVM) — it checks
    a handful of concrete, high-signal misconfigurations rather than
    matching against a CVE database. Several checks only produce a finding
    if this account has sudo — that's fine, they just contribute nothing
    rather than failing the whole audit."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port or 22,
            username=username,
            password=secret,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
    except paramiko.AuthenticationException:
        raise  # wrong credentials — deterministic, retrying changes nothing
    except (OSError, paramiko.SSHException) as exc:
        # Connection refused/reset, no route, timed out negotiating — on a
        # network with flaky links or a host mid-DHCP-renewal this can be
        # transient rather than "this host doesn't take SSH."
        raise TransientError(humanize_exception(exc)) from exc

    findings: list[dict] = []
    try:
        # Prefer the fully-resolved effective config (covers compiled-in
        # defaults, not just what's explicitly written in sshd_config).
        effective = _try_exec(client, "sudo -n sshd -T 2>/dev/null || sshd -T 2>/dev/null", timeout)
        config = _parse_effective_sshd_config(effective or "")
        if not config:
            raw = _try_exec(client, "cat /etc/ssh/sshd_config 2>/dev/null", timeout) or ""
            m = re.search(r"^\s*PermitRootLogin\s+(\S+)", raw, re.MULTILINE | re.IGNORECASE)
            if m:
                config["permitrootlogin"] = m.group(1).lower()
            m = re.search(r"^\s*PasswordAuthentication\s+(\S+)", raw, re.MULTILINE | re.IGNORECASE)
            if m:
                config["passwordauthentication"] = m.group(1).lower()

        if config.get("permitrootlogin") == "yes":
            findings.append(
                {
                    "severity": "high",
                    "cve": None,
                    "description": "SSH is configured to permit root login (PermitRootLogin yes).",
                    "recommendation": "Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config and use a non-root account with sudo instead.",
                }
            )

        if config.get("passwordauthentication") == "yes":
            findings.append(
                {
                    "severity": "medium",
                    "cve": None,
                    "description": "SSH permits password authentication, which is vulnerable to brute-force/credential-stuffing attacks.",
                    "recommendation": "Disable password authentication ('PasswordAuthentication no') and require SSH key-based auth instead.",
                }
            )

        for key, weak_terms, label in (
            ("ciphers", _WEAK_CIPHERS, "cipher"),
            ("macs", _WEAK_MACS, "MAC"),
            ("kexalgorithms", _WEAK_KEX, "key exchange"),
        ):
            algos = config.get(key, "")
            weak_found = [a for a in algos.split(",") if a and any(term in a.lower() for term in weak_terms)]
            if weak_found:
                findings.append(
                    {
                        "severity": "medium",
                        "cve": None,
                        "description": f"SSH allows weak {label} algorithm(s): {', '.join(weak_found)}.",
                        "recommendation": f"Remove the weak {label} algorithm(s) from sshd_config's '{key}' directive.",
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

        kernel = _try_exec(client, "uname -r", timeout)
        if kernel:
            m = re.match(r"(\d+)\.(\d+)", kernel)
            if m and int(m.group(1)) < 5:
                findings.append(
                    {
                        "severity": "low",
                        "cve": None,
                        "description": f"Kernel version looks old ({kernel}) — worth checking against your distro's supported/EOL kernel list.",
                        "recommendation": "Upgrade to a currently-supported kernel version for this distribution.",
                    }
                )

        empty_pw = _try_exec(client, "sudo -n awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null", timeout)
        if empty_pw:
            users = [u for u in empty_pw.splitlines() if u.strip()]
            if users:
                findings.append(
                    {
                        "severity": "critical",
                        "cve": None,
                        "description": f"Account(s) with no password set: {', '.join(users)}.",
                        "recommendation": "Set a strong password for (or disable) each listed account immediately.",
                    }
                )

        sudo_l = _try_exec(client, "sudo -n -l 2>/dev/null", timeout)
        if sudo_l and re.search(r"NOPASSWD:\s*ALL", sudo_l):
            findings.append(
                {
                    "severity": "high",
                    "cve": None,
                    "description": f"Account '{username}' has unrestricted passwordless sudo (NOPASSWD: ALL).",
                    "recommendation": "Restrict sudo rules to only the specific commands this account needs, and require a password.",
                }
            )

        listening = _try_exec(client, "ss -tln 2>/dev/null | tail -n +2", timeout) or _try_exec(
            client, "netstat -tln 2>/dev/null | tail -n +3", timeout
        )
        if listening:
            try:
                ports = sorted(
                    {line.split()[3].rsplit(":", 1)[-1] for line in listening.splitlines() if len(line.split()) > 3}
                )
            except Exception:
                ports = []
            if ports:
                findings.append(
                    {
                        "severity": "informational",
                        "cve": None,
                        "description": f"Listening TCP ports found: {', '.join(ports)}.",
                        "recommendation": None,
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
