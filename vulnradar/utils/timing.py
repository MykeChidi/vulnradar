# vulnradar/utils/timing.py

from __future__ import annotations

import time
from typing import Callable, Coroutine


async def measure_baseline(
    request_fn: Callable[[], Coroutine],
    samples: int = 3,
) -> float:
    """
    Measure the average response time for a request over ``samples`` attempts.

    Args:
        request_fn: An async callable that makes one request.  Must be a
                    coroutine function (e.g. ``lambda: session.get(url)``).
        samples:    Number of samples to average.  Three is sufficient for
                    most targets; increase to five for high-jitter networks.

    Returns:
        Average response time in seconds.
    """
    times: list[float] = []

    for _ in range(samples):
        start = time.monotonic()
        try:
            async with request_fn() as response:  # type: ignore[attr-defined]
                await response.read()
        except Exception:
            # Network errors during baseline measurement are silently skipped;
            # the caller should handle the case where all samples fail.
            pass
        times.append(time.monotonic() - start)

    if not times:
        return 0.0

    return sum(times) / len(times)


def is_time_based_hit(
    response_time: float,
    baseline: float,
    expected_sleep: float,
    tolerance: float = 0.5,
) -> bool:
    """
    Return ``True`` if ``response_time`` is consistent with a successful
    time-based blind injection.

    Args:
        response_time:  Observed elapsed time after injecting the sleep payload.
        baseline:       Average response time without any injection.
        expected_sleep: Sleep duration requested in the payload (e.g. 5).
        tolerance:      Allowed shortfall below the expected delay (seconds).

    Returns:
        True if the response time is consistent with the sleep being executed.
    """
    threshold = baseline + expected_sleep - tolerance
    return response_time >= threshold
