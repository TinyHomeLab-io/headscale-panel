from fastapi import Request

from .auth import get_session


class AuthRedirect(Exception):
    def __init__(self, target: str):
        self.target = target


def current_session(request: Request) -> dict | None:
    cfg = request.app.state.cfg
    sid = request.cookies.get(cfg.session_cookie_name)
    if not sid:
        return None
    return get_session(cfg.db_path, sid)


def require_authenticated(request: Request) -> dict:
    """Login required and MFA passed."""
    sess = current_session(request)
    if not sess:
        raise AuthRedirect("/login")
    if not sess["mfa_passed"]:
        if sess["totp_confirmed"]:
            raise AuthRedirect("/mfa")
        raise AuthRedirect("/enroll")
    return sess


def require_partial_auth(request: Request) -> dict:
    """Password-verified only (used for /mfa and /enroll)."""
    sess = current_session(request)
    if not sess:
        raise AuthRedirect("/login")
    return sess
