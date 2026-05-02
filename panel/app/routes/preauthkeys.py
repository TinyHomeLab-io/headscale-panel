import logging
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.preauthkeys")

# Preset durations for the create form.
EXPIRATION_PRESETS = [
    ("1 hour",   timedelta(hours=1)),
    ("24 hours", timedelta(hours=24)),
    ("7 days",   timedelta(days=7)),
    ("30 days",  timedelta(days=30)),
    ("90 days",  timedelta(days=90)),
]


def _expiration_iso(label: str) -> str | None:
    for name, delta in EXPIRATION_PRESETS:
        if name == label:
            return (datetime.now(timezone.utc) + delta).isoformat().replace("+00:00", "Z")
    return None


def _gather(hs) -> tuple[list[dict], list[dict]]:
    """Returns (users, all_keys_decorated). Headscale 0.28's LIST API ignores the
    user filter, so we call it once and use each key's embedded user."""
    users = hs.list_users()
    now = datetime.now(timezone.utc)
    keys: list[dict] = []
    seen_ids: set[str] = set()
    try:
        # user=any here; the API returns all keys regardless of filter.
        # Pass first user's ID so the request shape matches the API expectation.
        any_user = users[0]["id"] if users else "1"
        for k in hs.list_preauthkeys(any_user):
            kid = str(k.get("id"))
            if kid in seen_ids:
                continue
            seen_ids.add(kid)
            k = dict(k)
            k["_user"] = (k.get("user") or {}).get("name", "")
            k["_user_id"] = (k.get("user") or {}).get("id", "")
            exp = k.get("expiration") or ""
            k["_never_expires"] = exp.startswith("0001-01-01")
            if k["_never_expires"]:
                k["_expiration"] = "Never"
                k["_expired"] = False
            else:
                k["_expiration"] = exp[:19].replace("T", " ") if exp else "—"
                k["_expired"] = False
                if exp:
                    try:
                        k["_expired"] = datetime.fromisoformat(exp.replace("Z", "+00:00")) < now
                    except ValueError:
                        pass
            k["_used"] = bool(k.get("used"))
            k["_reusable"] = bool(k.get("reusable"))
            k["_ephemeral"] = bool(k.get("ephemeral"))
            keys.append(k)
    except httpx.HTTPError as e:
        log.warning("list_preauthkeys failed: %s", e)
    keys.sort(key=lambda k: k.get("createdAt", ""), reverse=True)
    return users, keys


@router.get("/preauthkeys")
def list_keys(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    users: list[dict] = []
    keys: list[dict] = []
    error = None
    if not hs:
        error = "Headscale client not configured"
    else:
        try:
            users, keys = _gather(hs)
        except httpx.HTTPError as e:
            error = f"Could not reach Headscale: {e}"
            log.warning("preauthkeys list failed: %s", e)

    return templates.TemplateResponse(
        request,
        "preauthkeys.html",
        {
            "username": sess["username"],
            "users": users,
            "keys": keys,
            "presets": [name for name, _ in EXPIRATION_PRESETS],
            "default_preset": "24 hours",
            "error": error,
            "created_key": request.query_params.get("created_key"),
            "expired": request.query_params.get("expired"),
        },
    )


@router.post("/preauthkeys")
def create_key(
    request: Request,
    user_id: str = Form(...),
    expiration: str = Form("24 hours"),
    reusable: bool = Form(False),
    ephemeral: bool = Form(False),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/preauthkeys", status_code=status.HTTP_303_SEE_OTHER)
    try:
        result = hs.create_preauthkey(
            user_id,
            expiration=_expiration_iso(expiration),
            reusable=reusable,
            ephemeral=ephemeral,
        )
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, "Couldn't create preauth key")

    key = result.get("key", "")
    return RedirectResponse(
        f"/preauthkeys?created_key={key}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/preauthkeys/expire")
def expire_key(
    request: Request,
    key_id: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/preauthkeys", status_code=status.HTTP_303_SEE_OTHER)
    try:
        hs.expire_preauthkey(key_id)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, "Couldn't expire key")
    return RedirectResponse(
        f"/preauthkeys?expired=id+{key_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/preauthkeys/delete")
def delete_key(
    request: Request,
    key_id: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/preauthkeys", status_code=status.HTTP_303_SEE_OTHER)
    try:
        hs.delete_preauthkey(key_id)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, "Couldn't delete key")
    return RedirectResponse(
        f"/preauthkeys?deleted=id+{key_id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _render_error(request, sess, hs, e: httpx.HTTPStatusError, prefix: str):
    detail = ""
    try:
        body = e.response.json()
        detail = body.get("message") or body.get("error") or ""
    except Exception:
        detail = e.response.text[:200]
    msg = f"{prefix}: {e.response.status_code} {detail}".strip()
    log.warning(msg)
    try:
        users, keys = _gather(hs)
    except httpx.HTTPError:
        users, keys = [], []
    return templates.TemplateResponse(
        request,
        "preauthkeys.html",
        {
            "username": sess["username"],
            "users": users,
            "keys": keys,
            "presets": [name for name, _ in EXPIRATION_PRESETS],
            "default_preset": "24 hours",
            "error": msg,
            "created_key": None,
            "expired": None,
        },
        status_code=400,
    )
