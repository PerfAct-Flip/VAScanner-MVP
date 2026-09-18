import time


class TransientError(Exception):
    """A failure that a retry might not repeat — a timeout, connection
    reset, or other network-level blip — as opposed to a deterministic one
    (bad credentials, malformed target) that will just fail the same way
    every time."""


def with_retry(fn, retries: int = 2, backoff_seconds: tuple[float, ...] = (5, 15)):
    """Runs fn(), retrying only on TransientError, with increasing backoff
    between attempts. Any other exception propagates immediately — there's
    no point retrying a failure that's going to happen again identically."""
    last_exc: TransientError | None = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except TransientError as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff_seconds[min(attempt, len(backoff_seconds) - 1)])
    raise last_exc
