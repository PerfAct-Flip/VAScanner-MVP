"""Translates raw exceptions into short, human-readable text before it ever
reaches a scan result or the backend's error_message — a customer looking
at a failed engine should see "the SSH credential was rejected", never
"[Errno -2] Name or service not known" or a bare paramiko stack trace."""

import socket

import paramiko


def humanize_exception(exc: Exception) -> str:
    if isinstance(exc, paramiko.AuthenticationException):
        return "The SSH credential was rejected — check the username and password."
    if isinstance(exc, socket.gaierror):
        return "Could not resolve the hostname — check that it's correct and reachable from the agent."
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused — the target may be down or not listening on the expected port."
    if isinstance(exc, TimeoutError):
        return "Connection timed out — the target may be unreachable or blocking the agent's network."
    if isinstance(exc, paramiko.SSHException):
        return f"SSH connection problem: {exc}"
    if isinstance(exc, OSError):
        return f"Network error reaching the target: {exc.strerror or exc}"

    message = str(exc).strip()
    lowered = message.lower()
    if "not found on path" in lowered:
        return "nmap isn't installed (or isn't on PATH) on the machine running the Presence Agent."
    if "requires root privileges" in lowered or ("permission" in lowered and "nmap" in lowered):
        return (
            "The Presence Agent doesn't have permission to run a full network scan — nmap needs root, "
            "or the cap_net_raw/cap_net_admin capabilities granted to it. Discovery may be incomplete "
            "or fail entirely until this is fixed on the agent's host."
        )
    if "discovery timed out" in lowered:
        return "Network discovery timed out — the target subnet may be too large, or too slow to respond."
    if lowered.startswith("nmap exited") or "discovery pass(es) failed" in lowered:
        return "Network discovery failed on the agent's machine — see the agent's own logs for details."
    return message or exc.__class__.__name__
