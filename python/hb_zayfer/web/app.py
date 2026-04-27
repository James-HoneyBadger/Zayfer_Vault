"""FastAPI application factory.

This module owns the web application's cross-cutting concerns:

- bearer-token authentication,
- per-client rate limiting, and
- static-file / SPA mounting.

The environment is read inside `create_app()` rather than at import time so
fresh app instances reflect the caller's configuration. This is important for
both tests and multi-process deployments.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from hb_zayfer.services import AppInfo
from hb_zayfer.web.routes import router

STATIC_DIR = Path(__file__).parent / "static"

# Default rate limiting configuration (per-IP). Actual values are read when
# each app instance is created so tests and subprocesses see fresh env state.
_DEFAULT_RATE_LIMIT = 60
_DEFAULT_RATE_WINDOW = 60


class _RateLimiter:
    """Simple thread-safe sliding-window rate limiter keyed by client IP."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """Return (allowed, remaining) for *key*."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            timestamps = self._requests[key]
            # Purge expired entries
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if not timestamps:
                # Remove empty key to prevent unbounded memory growth
                del self._requests[key]
                # Re-add for the current request
                self._requests[key] = [now]
                return True, self._max - 1
            if len(timestamps) >= self._max:
                return False, 0
            timestamps.append(now)
            return True, self._max - len(timestamps)


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    # Read environment-derived settings at app construction time so each app
    # instance starts from a clean, explicit configuration boundary.
    api_token = os.environ.get("HB_ZAYFER_API_TOKEN")
    rate_limit = int(os.environ.get("HB_ZAYFER_RATE_LIMIT", str(_DEFAULT_RATE_LIMIT)))
    rate_window = int(os.environ.get("HB_ZAYFER_RATE_WINDOW", str(_DEFAULT_RATE_WINDOW)))

    # The limiter is intentionally per-app, not global, to avoid state leaking
    # across unit tests or between independently created FastAPI instances.
    limiter = _RateLimiter(rate_limit, rate_window)

    info = AppInfo.current()
    app = FastAPI(
        title=info.api_title,
        description=f"{info.description} — Web Interface",
        version=info.version,
    )

    # CORS — restrict to localhost origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )

    # Bearer-token auth middleware (if token is configured)
    @app.middleware("http")
    async def _auth_middleware(request: Request, call_next):
        if api_token is not None:
            # Allow static files and docs without auth
            path = request.url.path
            if not (
                path.startswith("/static")
                or path == "/"
                or path.startswith("/docs")
                or path.startswith("/openapi")
            ):
                auth = request.headers.get("authorization", "")
                expected = f"Bearer {api_token}"
                # Timing-safe comparison to prevent token-guessing side-channel attacks
                if not secrets.compare_digest(auth, expected):
                    return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    # Per-IP rate limiting middleware
    @app.middleware("http")
    async def _rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        allowed, remaining = limiter.is_allowed(client_ip)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Try again later."},
                status_code=429,
                headers={
                    "Retry-After": str(rate_window),
                    "X-RateLimit-Limit": str(rate_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    app.include_router(router, prefix="/api")

    # Serve static files (HTML/JS/CSS)
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static-assets")
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")

    return app


def main() -> None:
    """Run the web server via uvicorn."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="HB_Zayfer Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=int(os.environ.get("HB_ZAYFER_PORT", "8000")),
        help="Port number (default: 8000, or HB_ZAYFER_PORT env)",
    )
    args = parser.parse_args()

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
