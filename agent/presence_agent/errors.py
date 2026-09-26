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
    return message or exc.__class__.__name__
