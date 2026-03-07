"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from hb_zayfer.web.routes import router
import hb_zayfer as hbz

STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""
    app = FastAPI(
        title="HB_Zayfer",
        description="Encryption/Decryption Suite — Web Interface",
        version=hbz.version(),
    )

    app.include_router(router, prefix="/api")

    # Serve static files (HTML/JS/CSS)
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static-assets")
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")

    return app


def main() -> None:
    """Run the web server via uvicorn."""
    import uvicorn

    app = create_app()
    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
