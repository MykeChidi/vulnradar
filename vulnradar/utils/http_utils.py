# vulnradar/utils/http_utils.py - Shared HTTP helpers

import aiohttp

# Maximum bytes to read from a single HTTP response.
# Prevents memory exhaustion when a malicious target streams a huge body (F-01).
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB


async def safe_read_response(
    response: aiohttp.ClientResponse,
    limit: int = MAX_RESPONSE_BYTES,
) -> str:
    """
    Read at most ``limit`` bytes from an aiohttp response and return
    decoded text (replacing undecodable bytes rather than raising).

    Use this instead of ``await response.text()`` anywhere in recon modules
    to prevent unbounded memory consumption from attacker-controlled responses.
    """
    body = await response.content.read(limit)
    return body.decode(errors="replace")
