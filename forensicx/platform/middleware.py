"""HTTP middleware for logging and rate limiting."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


LOGGER = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log each HTTP request and enforce a simple in-process rate limit."""

    def __init__(self, app: object) -> None:
        """Initialize the middleware with an empty request ledger."""
        super().__init__(app)
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable[[Request], object]) -> Response:
        """Log request metadata, apply rate limiting, and return the response."""
        started = time.perf_counter()
        settings = request.app.state.settings
        client = request.client.host if request.client else "unknown"
        if self._is_limited(client, settings.request_limit_per_minute):
            LOGGER.warning("Rate limit exceeded for %s on %s", client, request.url.path)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        LOGGER.info("%s %s %s %.2fms", request.method, request.url.path, response.status_code, duration_ms)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def _is_limited(self, client: str, limit: int) -> bool:
        """Return whether a client has exceeded the per-minute request limit."""
        now = time.time()
        ledger = self._requests[client]
        while ledger and now - ledger[0] > 60:
            ledger.popleft()
        ledger.append(now)
        return len(ledger) > limit
