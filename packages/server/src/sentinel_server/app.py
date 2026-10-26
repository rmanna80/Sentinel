"""Application factory."""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import ModuleType

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select

from . import __version__, audit, phases
from .config import Settings, get_settings
from .db import Base, init_engine, session_scope
from .migrate import upgrade_to_head
from .models import User
from .security import new_token
from .security.middleware import BodySizeLimitMiddleware, HostCheckMiddleware, SecurityHeadersMiddleware
from .services import hooks
from .services.ingest import expire_stale_scans

log = logging.getLogger(__name__)


class BackgroundLoop:
    """Lease expiry plus every phase module's ``tick``, on one daemon thread."""

    def __init__(self, interval: float, modules: list[ModuleType]) -> None:
        self.interval = interval
        self.modules = [m for m in modules if hasattr(m, "tick")]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinel-background", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> None:
        try:
            with session_scope() as db:
                expire_stale_scans(db)
        except Exception:
            log.exception("lease expiry failed")
        try:
            audit.seal()  # anything a crash left unsealed
        except Exception:
            log.exception("audit sealing failed")
        for module in self.modules:
            try:
                with session_scope() as db:
                    module.tick(db)
            except Exception:
                log.exception("background tick for %s failed", module.__name__)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.run_once()


def _prepare_setup_token(app: FastAPI, settings: Settings) -> None:
    with session_scope() as db:
        users = db.execute(select(func.count(User.id))).scalar_one()
    token_file = settings.data_dir / "setup-token.txt"
    if users:
        app.state.setup_token = None
        token_file.unlink(missing_ok=True)
        return
    token = new_token(12)
    app.state.setup_token = token
    token_file.write_text(token + "\n", encoding="utf-8")
    banner = (f"\n  First-time setup: open http://127.0.0.1:{settings.port} and enter this setup token:\n\n"
              f"      {token}\n\n  (also saved to {token_file})\n")
    print(banner, flush=True)


def create_app(settings: Settings | None = None, *, start_background: bool = True,
               run_migrations: bool = True) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()
    init_engine(settings.db_url)
    if run_migrations:
        upgrade_to_head(settings.db_url)
    else:
        from .db import get_engine

        Base.metadata.create_all(get_engine())

    hooks.clear()
    modules = phases.load()
    for m in modules:
        if hasattr(m, "register_hooks"):
            m.register_hooks()
    loop = BackgroundLoop(settings.scheduler_tick_seconds, modules)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        _prepare_setup_token(app, settings)
        if start_background:
            loop.start()
        yield
        loop.stop()

    app = FastAPI(title="Sentinel", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs" if settings.mode.value != "production" else None,
                  redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.background = loop
    app.state.setup_token = None

    from .api import admin, agent, auth, dashboard, devices, findings, scans

    for r in (auth.router, agent.router, devices.router, scans.router, findings.router, dashboard.router,
              admin.router):
        app.include_router(r)
    for m in modules:
        if hasattr(m, "router"):
            app.include_router(m.router)

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "mode": settings.mode.value}

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    _mount_dashboard(app, settings.static_dir())

    # Order matters: the last one added runs first. Host check, then body size, then headers.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, default_limit=2 * 1024 * 1024,
                       prefix_limits={"/api/agent/": 32 * 1024 * 1024})
    app.add_middleware(HostCheckMiddleware, allowed_hosts=settings.allowed_hosts)
    return app


def _mount_dashboard(app: FastAPI, static: Path) -> None:
    index = static / "index.html"
    if (static / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False, response_model=None)
    def spa(path: str) -> FileResponse | HTMLResponse:
        if path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (static / path).resolve()
        # Only serve real files inside the static folder; everything else gets the app shell.
        if path and candidate.is_file() and static.resolve() in candidate.parents:
            return FileResponse(candidate)
        if index.exists():
            return FileResponse(index)
        return HTMLResponse(
            "<h1>Sentinel API is running</h1><p>The dashboard has not been built. "
            "Run <code>scripts\\build-web.ps1</code> (or <code>npm run build</code> in <code>web/</code>).</p>"
        )
