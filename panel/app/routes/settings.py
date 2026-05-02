"""Settings page — server URL, TLS, and raw YAML editor for Headscale's config.yaml.

DNS configuration lives at /dns (separate page).
"""
import logging
from urllib.parse import quote_plus

import yaml
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated
from ..headscale_yaml import load_doc, read_raw, restart_and_wait, save_doc, write_raw

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.settings")


@router.get("/settings")
def view_settings(request: Request, sess: dict = Depends(require_authenticated)):
    cfg = request.app.state.cfg
    doc = load_doc(cfg.headscale_config_path)
    raw_text = read_raw(cfg.headscale_config_path)

    # TLS mode detection
    le_hostname = doc.get("tls_letsencrypt_hostname", "") or ""
    cert_path = doc.get("tls_cert_path", "") or ""
    key_path = doc.get("tls_key_path", "") or ""
    if le_hostname:
        tls_mode = "letsencrypt"
    elif cert_path and key_path:
        tls_mode = "manual"
    else:
        tls_mode = "none"

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "username": sess["username"],
            "config_path": cfg.headscale_config_path,
            "server_url": doc.get("server_url", ""),
            "tls_mode": tls_mode,
            "tls_le_hostname": le_hostname,
            "tls_le_challenge": doc.get("tls_letsencrypt_challenge_type", "HTTP-01"),
            "tls_le_listen": doc.get("tls_letsencrypt_listen", ":http"),
            "tls_le_cache_dir": doc.get("tls_letsencrypt_cache_dir", "/var/lib/headscale/cache"),
            "tls_cert_path": cert_path,
            "tls_key_path": key_path,
            "raw_yaml": raw_text,
            "flash": request.query_params.get("flash"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/settings/structured")
async def save_structured(
    request: Request,
    sess: dict = Depends(require_authenticated),
):
    cfg = request.app.state.cfg
    form = await request.form()

    server_url = (form.get("server_url") or "").strip()
    tls_mode = (form.get("tls_mode") or "none").strip()

    doc = load_doc(cfg.headscale_config_path)
    if server_url:
        doc["server_url"] = server_url

    # TLS — set the fields that match the chosen mode, clear the others.
    if tls_mode == "letsencrypt":
        doc["tls_letsencrypt_hostname"] = (form.get("tls_le_hostname") or "").strip()
        doc["tls_letsencrypt_challenge_type"] = (form.get("tls_le_challenge") or "HTTP-01").strip()
        doc["tls_letsencrypt_listen"] = (form.get("tls_le_listen") or ":http").strip()
        doc["tls_letsencrypt_cache_dir"] = (form.get("tls_le_cache_dir") or "/var/lib/headscale/cache").strip()
        doc["tls_cert_path"] = ""
        doc["tls_key_path"] = ""
    elif tls_mode == "manual":
        doc["tls_cert_path"] = (form.get("tls_cert_path") or "").strip()
        doc["tls_key_path"] = (form.get("tls_key_path") or "").strip()
        doc["tls_letsencrypt_hostname"] = ""
    else:
        doc["tls_letsencrypt_hostname"] = ""
        doc["tls_cert_path"] = ""
        doc["tls_key_path"] = ""

    try:
        save_doc(cfg.headscale_config_path, doc)
    except Exception as e:
        log.exception("config write failed")
        return RedirectResponse(
            f"/settings?error={quote_plus(f'Could not write config: {e}')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    err = restart_and_wait(cfg.headscale_url, cfg.headscale_container)
    if err:
        return RedirectResponse(
            f"/settings?error={quote_plus(err)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(
        "/settings?flash=Settings+saved+%E2%80%94+Headscale+restarted",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/raw")
async def save_raw(
    request: Request,
    raw_yaml: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    cfg = request.app.state.cfg

    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        return RedirectResponse(
            f"/settings?error={quote_plus(f'YAML parse error: {e}')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if parsed is not None and not isinstance(parsed, dict):
        return RedirectResponse(
            f"/settings?error={quote_plus('Top-level YAML must be a mapping (key: value)')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        write_raw(cfg.headscale_config_path, raw_yaml)
    except Exception as e:
        log.exception("raw config write failed")
        return RedirectResponse(
            f"/settings?error={quote_plus(f'Could not write config: {e}')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    err = restart_and_wait(cfg.headscale_url, cfg.headscale_container)
    if err:
        return RedirectResponse(
            f"/settings?error={quote_plus(err)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return RedirectResponse(
        "/settings?flash=Raw+config+saved+%E2%80%94+Headscale+restarted",
        status_code=status.HTTP_303_SEE_OTHER,
    )
