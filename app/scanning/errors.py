"""Translates raw exceptions into short, human-readable text before it ever
reaches a ScanEngine.error_message or an API response — a customer looking
at a failed scan should see "could not resolve the hostname", never
"[Errno -2] Name or service not known"."""

import socket


def humanize_exception(exc: Exception) -> str:
    if isinstance(exc, socket.gaierror):
        return "Could not resolve the hostname — check that it's correct and reachable from the scanner."
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused — the target may be down or not listening on the expected port."
    if isinstance(exc, TimeoutError):
        return "Connection timed out — the target may be unreachable or blocking the scanner's network."
    if isinstance(exc, OSError):
        return f"Network error reaching the target: {exc.strerror or exc}"
    message = str(exc).strip()
    return message or exc.__class__.__name__
