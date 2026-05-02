import logging

import httpx
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.users")


def _ctx(request: Request, sess: dict, **extra) -> dict:
    base = {
        "username": sess["username"],
        "users": [],
        "error": None,
        "created": None,
        "deleted": None,
        "renamed": None,
    }
    base.update(extra)
    return base


@router.get("/users")
def list_users(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    error = None
    users: list[dict] = []
    try:
        users = hs.list_users() if hs else []
        if not hs:
            error = "Headscale client not configured (PANEL_HEADSCALE_API_KEY missing)"
    except httpx.HTTPError as e:
        log.warning("list_users failed: %s", e)
        error = f"Could not reach Headscale: {e}"
    return templates.TemplateResponse(
        request,
        "users.html",
        _ctx(
            request,
            sess,
            users=users,
            error=error,
            created=request.query_params.get("created"),
            deleted=request.query_params.get("deleted"),
            renamed=request.query_params.get("renamed"),
        ),
    )


@router.post("/users")
def create_user(
    request: Request,
    name: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    name = name.strip()
    if not name or not hs:
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    try:
        hs.create_user(name)
    except httpx.HTTPStatusError as e:
        log.warning("create_user(%s) failed: %s", name, e)
        return templates.TemplateResponse(
            request,
            "users.html",
            _ctx(
                request,
                sess,
                users=hs.list_users(),
                error=_format_hs_error(e, "Couldn't create user"),
            ),
            status_code=400,
        )
    return RedirectResponse(f"/users?created={name}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/rename")
def rename_user(
    request: Request,
    user_id: str,
    new_name: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    new_name = new_name.strip()
    if not hs or not new_name:
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)
    try:
        hs.rename_user(user_id, new_name)
    except httpx.HTTPStatusError as e:
        return templates.TemplateResponse(
            request,
            "users.html",
            _ctx(
                request,
                sess,
                users=hs.list_users(),
                error=_format_hs_error(e, f"Couldn't rename to '{new_name}'"),
            ),
            status_code=400,
        )
    return RedirectResponse(f"/users?renamed={new_name}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/delete")
def delete_user(
    request: Request,
    user_id: str,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/users", status_code=status.HTTP_303_SEE_OTHER)

    # Resolve name for flash before deletion (best effort)
    name = user_id
    try:
        for u in hs.list_users():
            if str(u.get("id")) == str(user_id):
                name = u.get("name", user_id)
                break
    except httpx.HTTPError:
        pass

    try:
        hs.delete_user(user_id)
    except httpx.HTTPStatusError as e:
        log.warning("delete_user(%s) failed: %s", user_id, e)
        return templates.TemplateResponse(
            request,
            "users.html",
            _ctx(
                request,
                sess,
                users=hs.list_users(),
                error=_format_hs_error(
                    e,
                    f"Couldn't delete {name}",
                    hint="If the user has nodes, expire/delete them first.",
                ),
            ),
            status_code=400,
        )

    return RedirectResponse(f"/users?deleted={name}", status_code=status.HTTP_303_SEE_OTHER)


def _format_hs_error(e: httpx.HTTPStatusError, prefix: str, hint: str | None = None) -> str:
    detail = ""
    try:
        body = e.response.json()
        detail = body.get("message") or body.get("error") or ""
    except Exception:
        detail = e.response.text[:200]
    msg = f"{prefix}: {e.response.status_code} {detail}".rstrip()
    if hint:
        msg += f" — {hint}"
    return msg
