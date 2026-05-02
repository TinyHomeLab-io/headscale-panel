import pyotp
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..auth import (
    confirm_totp,
    create_session,
    delete_session,
    get_user_by_username,
    make_qr_svg,
    make_totp_uri,
    mark_session_mfa_passed,
    set_totp_secret,
    verify_password,
    verify_totp,
)
from ..deps import current_session, require_partial_auth

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/login")
def get_login(request: Request):
    sess = current_session(request)
    if sess and sess["mfa_passed"]:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def post_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    cfg = request.app.state.cfg
    user = get_user_by_username(cfg.db_path, username)
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password"}, status_code=400
        )

    sid = create_session(cfg.db_path, user["id"], cfg.session_lifetime_secs)
    target = "/mfa" if user["totp_confirmed"] else "/enroll"
    resp = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(
        cfg.session_cookie_name,
        sid,
        max_age=cfg.session_lifetime_secs,
        httponly=True,
        secure=cfg.secure_cookies,
        samesite="lax",
    )
    return resp


@router.get("/mfa")
def get_mfa(request: Request, sess: dict = Depends(require_partial_auth)):
    if not sess["totp_confirmed"]:
        return RedirectResponse("/enroll", status_code=status.HTTP_303_SEE_OTHER)
    if sess["mfa_passed"]:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "mfa.html", {"error": None})


@router.post("/mfa")
def post_mfa(
    request: Request,
    code: str = Form(...),
    sess: dict = Depends(require_partial_auth),
):
    cfg = request.app.state.cfg
    user = _get_user(cfg.db_path, sess["user_id"])
    if not user or not user["totp_confirmed"]:
        return RedirectResponse("/enroll", status_code=status.HTTP_303_SEE_OTHER)

    if not verify_totp(user["totp_secret"], code.strip()):
        return templates.TemplateResponse(
            request, "mfa.html", {"error": "Invalid code, try again"}, status_code=400
        )

    mark_session_mfa_passed(cfg.db_path, sess["id"])
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/enroll")
def get_enroll(request: Request, sess: dict = Depends(require_partial_auth)):
    cfg = request.app.state.cfg
    user = _get_user(cfg.db_path, sess["user_id"])

    if user["totp_confirmed"]:
        target = "/" if sess["mfa_passed"] else "/mfa"
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    secret = user["totp_secret"]
    if not secret:
        secret = pyotp.random_base32()
        set_totp_secret(cfg.db_path, user["id"], secret)

    uri = make_totp_uri(secret, user["username"], cfg.totp_issuer)
    qr_svg = make_qr_svg(uri)

    return templates.TemplateResponse(
        request,
        "enroll.html",
        {"secret": secret, "uri": uri, "qr_svg": qr_svg, "error": None},
    )


@router.post("/enroll")
def post_enroll(
    request: Request,
    code: str = Form(...),
    sess: dict = Depends(require_partial_auth),
):
    cfg = request.app.state.cfg
    user = _get_user(cfg.db_path, sess["user_id"])
    if not user or not user["totp_secret"]:
        return RedirectResponse("/enroll", status_code=status.HTTP_303_SEE_OTHER)

    if not verify_totp(user["totp_secret"], code.strip()):
        # Re-render with same secret
        uri = make_totp_uri(user["totp_secret"], user["username"], cfg.totp_issuer)
        qr_svg = make_qr_svg(uri)
        return templates.TemplateResponse(
            request,
            "enroll.html",
            {
                "secret": user["totp_secret"],
                "uri": uri,
                "qr_svg": qr_svg,
                "error": "Invalid code, try again",
            },
            status_code=400,
        )

    confirm_totp(cfg.db_path, user["id"])
    mark_session_mfa_passed(cfg.db_path, sess["id"])
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/logout")
def post_logout(request: Request):
    cfg = request.app.state.cfg
    sid = request.cookies.get(cfg.session_cookie_name)
    if sid:
        delete_session(cfg.db_path, sid)
    resp = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie(cfg.session_cookie_name)
    return resp


def _get_user(db_path: str, user_id: int) -> dict | None:
    from ..auth import get_user_by_id

    return get_user_by_id(db_path, user_id)
