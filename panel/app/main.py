import logging

from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import bootstrap_admin, cleanup_expired_sessions
from .config import load_config
from .db import init_db
from .deps import AuthRedirect
from .headscale import HeadscaleClient
from .routes import account as account_routes
from .routes import auth as auth_routes
from .routes import dashboard as dashboard_routes
from .routes import diagnostics as diagnostics_routes
from .routes import dns as dns_routes
from .routes import nodes as nodes_routes
from .routes import policy as policy_routes
from .routes import preauthkeys as preauthkeys_routes
from .routes import settings as settings_routes
from .routes import users as users_routes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("panel")


def create_app() -> FastAPI:
    cfg = load_config()
    app = FastAPI(title="Headscale Panel")
    app.state.cfg = cfg

    @app.on_event("startup")
    def on_startup():
        log.info("initialising panel.sqlite at %s", cfg.db_path)
        init_db(cfg.db_path)
        cleanup_expired_sessions(cfg.db_path)
        if cfg.bootstrap_user and cfg.bootstrap_pass:
            bootstrap_admin(cfg.db_path, cfg.bootstrap_user, cfg.bootstrap_pass)
            log.info("bootstrap user ensured: %s", cfg.bootstrap_user)
        else:
            log.warning("PANEL_BOOTSTRAP_USER/PASSWORD not set — no users will be auto-created")
        if cfg.headscale_api_key:
            app.state.hs = HeadscaleClient(cfg.headscale_url, cfg.headscale_api_key)
            log.info("headscale client initialised: %s", cfg.headscale_url)
        else:
            app.state.hs = None
            log.warning("PANEL_HEADSCALE_API_KEY not set — Headscale integration disabled")

    @app.on_event("shutdown")
    def on_shutdown():
        if getattr(app.state, "hs", None):
            app.state.hs.close()

    @app.exception_handler(AuthRedirect)
    async def _auth_redirect(request: Request, exc: AuthRedirect):
        return RedirectResponse(exc.target, status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/health")
    def health():
        return {"ok": True}

    app.mount("/static", StaticFiles(directory="app/static"), name="static")

    app.include_router(auth_routes.router)
    app.include_router(dashboard_routes.router)
    app.include_router(users_routes.router)
    app.include_router(nodes_routes.router)
    app.include_router(preauthkeys_routes.router)
    app.include_router(policy_routes.router)
    app.include_router(diagnostics_routes.router)
    app.include_router(dns_routes.router)
    app.include_router(settings_routes.router)
    app.include_router(account_routes.router)
    return app


app = create_app()
