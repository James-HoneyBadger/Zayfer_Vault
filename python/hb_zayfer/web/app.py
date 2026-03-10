"""FastAPI application factory."""

from __future__ import annotations

import os
import secrets
import time
import threading
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from hb_zayfer.web.routes import router
import hb_zayfer as hbz

STATIC_DIR = Path(__file__).parent / "static"

# Bearer token for API authentication.
# Set HB_ZAYFER_API_TOKEN env-var to require token auth on every request.
# If unset, the API is openly accessible (suitable for local-only use).
_API_TOKEN: str | None = os.environ.get("HB_ZAYFER_API_TOKEN")

# Rate limiting configuration (per-IP).
# Defaults: 60 requests per 60-second window.  Override via env-vars.
_RATE_LIMIT: int = int(os.environ.get("HB_ZAYFER_RATE_LIMIT", "60"))
_RATE_WINDOW: int = int(os.environ.get("HB_ZAYFER_RATE_WINDOW", "60"))


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


_limiter = _RateLimiter(_RATE_LIMIT, _RATE_WINDOW)


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    app = FastAPI(
        title="HB_Zayfer",
        description="Encryption/Decryption Suite — Web Interface",
        version=hbz.version(),
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
        if _API_TOKEN is not None:
            # Allow static files and docs without auth
            path = request.url.path
            if not (path.startswith("/static") or path == "/" or path.startswith("/docs") or path.startswith("/openapi")):
                auth = request.headers.get("authorization", "")
                expected = f"Bearer {_API_TOKEN}"
                # Timing-safe comparison to prevent token-guessing side-channel attacks
                if not secrets.compare_digest(auth, expected):
                    return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    # Per-IP rate limiting middleware
    @app.middleware("http")
    async def _rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        allowed, remaining = _limiter.is_allowed(client_ip)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Try again later."},
                status_code=429,
                headers={"Retry-After": str(_RATE_WINDOW)},
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(_RATE_LIMIT)
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
    parser.add_argument("--port", "-p", type=int, default=int(os.environ.get("HB_ZAYFER_PORT", "8000")),
                        help="Port number (default: 8000, or HB_ZAYFER_PORT env)")
    args = parser.parse_args()

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
