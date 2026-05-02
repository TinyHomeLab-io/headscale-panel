import logging

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import (
    delete_other_sessions,
    get_user_by_id,
    reset_totp,
    update_password,
    verify_password,
)
from ..db import connect
from ..deps import require_authenticated

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.account")

MIN_PASSWORD_LEN = 12


@router.get("/account")
def get_account(request: Request, sess: dict = Depends(require_authenticated)):
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "username": sess["username"],
            "min_password_len": MIN_PASSWORD_LEN,
            "password_changed": request.query_params.get("password_changed"),
            "totp_reset": request.query_params.get("totp_reset"),
            "error": None,
        },
    )


@router.post("/account/password")
def post_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    cfg = request.app.state.cfg
    user = get_user_by_id(cfg.db_path, sess["user_id"])
    if not user:
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)

    error = _validate_password_change(user, current_password, new_password, confirm_password)
    if error:
        return templates.TemplateResponse(
            request,
            "account.html",
            {
                "username": sess["username"],
                "min_password_len": MIN_PASSWORD_LEN,
                "password_changed": None,
                "totp_reset": None,
                "error": error,
            },
            status_code=400,
        )

    update_password(cfg.db_path, user["id"], new_password)
    revoked = delete_other_sessions(cfg.db_path, user["id"], sess["id"])
    log.info("password changed for user_id=%s; %d other sessions revoked", user["id"], revoked)
    return RedirectResponse(
        f"/account?password_changed=1&revoked={revoked}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/account/totp/reset")
def post_reset_totp(
    request: Request,
    current_password: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    cfg = request.app.state.cfg
    user = get_user_by_id(cfg.db_path, sess["user_id"])
    if not user or not verify_password(current_password, user["password_hash"]):
        return templates.TemplateResponse(
            request,
            "account.html",
            {
                "username": sess["username"],
                "min_password_len": MIN_PASSWORD_LEN,
                "password_changed": None,
                "totp_reset": None,
                "error": "Current password incorrect",
            },
            status_code=400,
        )

    reset_totp(cfg.db_path, user["id"])
    # Force re-enrollment immediately: drop all sessions; user has to re-login + enroll.
    with connect(cfg.db_path) as c:
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    log.info("TOTP reset for user_id=%s", user["id"])

    resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(cfg.session_cookie_name)
    return resp


def _validate_password_change(
    user: dict, current: str, new: str, confirm: str
) -> str | None:
    if not verify_password(current, user["password_hash"]):
        return "Current password is incorrect"
    if new != confirm:
        return "New password and confirmation do not match"
    if len(new) < MIN_PASSWORD_LEN:
        return f"New password must be at least {MIN_PASSWORD_LEN} characters"
    if new == current:
        return "New password must differ from current"
    return None
