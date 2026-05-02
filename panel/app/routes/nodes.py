import ipaddress
import logging
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated
from ..headscale_db import (
    clear_node_approved_routes,
    clear_node_tags,
    list_node_ips,
    restart_headscale,
    update_node_ips,
    update_node_user,
    wait_until_responsive,
)
from ..headscale_yaml import load_doc

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.nodes")

ONLINE_WINDOW = timedelta(minutes=5)


def _online_for(node: dict) -> bool:
    """Prefer Headscale's authoritative `online` flag; fall back to lastSeen recency."""
    if "online" in node and isinstance(node["online"], bool):
        return node["online"]
    last_seen = node.get("lastSeen")
    if not last_seen:
        return False
    try:
        ts = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return False
    return datetime.now(timezone.utc) - ts < ONLINE_WINDOW


def _decorate(nodes: list[dict]) -> list[dict]:
    out = []
    for n in nodes:
        n = dict(n)
        n["_online"] = _online_for(n)
        n["_user_name"] = (n.get("user") or {}).get("name", "")
        n["_ips"] = ", ".join(n.get("ipAddresses", []) or [])
        ls = n.get("lastSeen") or ""
        n["_last_seen"] = ls[:19].replace("T", " ") if ls else "—"
        out.append(n)
    return out


@router.get("/nodes")
def list_nodes(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    nodes: list[dict] = []
    users: list[dict] = []
    error = None
    if not hs:
        error = "Headscale client not configured"
    else:
        try:
            nodes = _decorate(hs.list_nodes())
            users = hs.list_users()
        except httpx.HTTPError as e:
            log.warning("list_nodes failed: %s", e)
            error = f"Headscale unreachable: {e}. It may be restarting — try refreshing in a moment."
    cfg = request.app.state.cfg
    hs_doc = load_doc(cfg.headscale_config_path)
    server_url = hs_doc.get("server_url", "http://localhost:8080")

    return templates.TemplateResponse(
        request,
        "nodes.html",
        {
            "username": sess["username"],
            "nodes": nodes,
            "users": users,
            "server_url": server_url,
            "error": error,
            "renamed": request.query_params.get("renamed"),
            "expired": request.query_params.get("expired"),
            "deleted": request.query_params.get("deleted"),
            "registered": request.query_params.get("registered"),
        },
    )


@router.post("/api/quick-preauth-key")
def api_quick_preauth_key(
    request: Request,
    user_id: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    """Create a 24h single-use preauth key for the given user. Returns JSON {key}."""
    from fastapi.responses import JSONResponse

    hs = request.app.state.hs
    if not hs:
        return JSONResponse({"error": "Headscale not configured"}, status_code=503)
    expiration = (
        (datetime.now(timezone.utc) + timedelta(hours=24))
        .isoformat()
        .replace("+00:00", "Z")
    )
    try:
        result = hs.create_preauthkey(
            user_id, expiration=expiration, reusable=False, ephemeral=False
        )
    except httpx.HTTPStatusError as e:
        return JSONResponse(
            {"error": e.response.text[:200] or str(e)},
            status_code=e.response.status_code,
        )
    except httpx.HTTPError as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return JSONResponse({"key": result.get("key", ""), "user_id": user_id})


@router.post("/nodes/register")
def register_node(
    request: Request,
    user_id: str = Form(...),
    node_key: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/nodes", status_code=status.HTTP_303_SEE_OTHER)

    node_key = node_key.strip()
    # Accept full URL paste: http://host/register/<id>
    if "/register/" in node_key:
        node_key = node_key.split("/register/", 1)[1].strip().rstrip("/")
    # Strip "nodekey:" prefix (legacy format, just in case)
    if node_key.startswith("nodekey:"):
        node_key = node_key[len("nodekey:"):]
    # Strip any trailing query/fragment
    for sep in ("?", "#", " "):
        if sep in node_key:
            node_key = node_key.split(sep, 1)[0]

    # Resolve user_id → username (the register endpoint wants the name, not ID).
    username = None
    try:
        for u in hs.list_users():
            if str(u.get("id")) == str(user_id):
                username = u.get("name")
                break
    except httpx.HTTPError as e:
        log.warning("list_users for register failed: %s", e)
    if not username:
        return _render_message(request, sess, hs, "Selected user no longer exists")

    try:
        result = hs.register_node(username, node_key)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, "Registration failed")

    name = result.get("givenName") or result.get("name") or "node"
    return RedirectResponse(
        f"/nodes?registered={name}", status_code=status.HTTP_303_SEE_OTHER
    )


def _render_message(request, sess, hs, msg: str):
    try:
        nodes = _decorate(hs.list_nodes())
        users = hs.list_users()
    except httpx.HTTPError:
        nodes, users = [], []
    return templates.TemplateResponse(
        request,
        "nodes.html",
        {
            "username": sess["username"],
            "nodes": nodes,
            "users": users,
            "error": msg,
            "renamed": None,
            "expired": None,
            "deleted": None,
            "registered": None,
        },
        status_code=400,
    )


@router.post("/nodes/{node_id}/rename")
def rename_node(
    request: Request,
    node_id: str,
    new_name: str = Form(...),
    return_to: str = Form("list"),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    new_name = new_name.strip()
    if not hs or not new_name:
        target = f"/nodes/{node_id}" if return_to == "detail" else "/nodes"
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    try:
        hs.rename_node(node_id, new_name)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, f"Rename to '{new_name}' failed")
    if return_to == "detail":
        return RedirectResponse(f"/nodes/{node_id}?flash=Renamed+to+{new_name}", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(f"/nodes?renamed={new_name}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/nodes/{node_id}")
def node_detail(
    request: Request,
    node_id: str,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/nodes", status_code=status.HTTP_303_SEE_OTHER)
    try:
        node = hs.get_node(node_id)
        users = hs.list_users()
    except httpx.HTTPError as e:
        log.warning("get_node(%s) failed: %s", node_id, e)
        return templates.TemplateResponse(
            request,
            "service_unavailable.html",
            {
                "username": sess["username"],
                "title": "Headscale unreachable",
                "detail": str(e),
                "retry_url": f"/nodes/{node_id}",
            },
            status_code=503,
        )

    node["_online"] = _online_for(node)
    available = node.get("availableRoutes", []) or []
    approved = set(node.get("approvedRoutes", []) or [])

    # Separate exit-node routes (0.0.0.0/0 + ::/0) from subnet routes.
    EXIT_ROUTES = {"0.0.0.0/0", "::/0"}
    advertises_exit = bool(EXIT_ROUTES & set(available))
    exit_approved = EXIT_ROUTES.issubset(approved)
    subnet_routes = [r for r in available if r not in EXIT_ROUTES]
    # Always include currently-approved subnet routes even if no longer advertised.
    for r in approved:
        if r not in EXIT_ROUTES and r not in subnet_routes:
            subnet_routes.append(r)

    cfg = request.app.state.cfg
    ips = node.get("ipAddresses") or []
    cur_v4 = next((ip for ip in ips if ":" not in ip), "")
    cur_v6 = next((ip for ip in ips if ":" in ip), "")
    # Read base_domain from Headscale's config.yaml (managed by /dns).
    hs_doc = load_doc(cfg.headscale_config_path)
    base_domain = (hs_doc.get("dns") or {}).get("base_domain", "")
    magic_dns_name = (
        f"{node.get('givenName')}.{base_domain}".rstrip(".")
        if node.get("givenName") and base_domain
        else ""
    )

    return templates.TemplateResponse(
        request,
        "node_detail.html",
        {
            "username": sess["username"],
            "node": node,
            "users": users,
            "advertises_exit": advertises_exit,
            "exit_approved": exit_approved,
            "subnet_routes": [(r, r in approved) for r in subnet_routes],
            "tags": node.get("tags", []) or [],
            "magic_dns_name": magic_dns_name,
            "current_ipv4": cur_v4,
            "current_ipv6": cur_v6,
            "prefix_v4": cfg.prefix_v4,
            "prefix_v6": cfg.prefix_v6,
            "flash": request.query_params.get("flash"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/nodes/{node_id}/ip")
def update_ip(
    request: Request,
    node_id: str,
    ipv4: str = Form(""),
    ipv6: str = Form(""),
    sess: dict = Depends(require_authenticated),
):
    cfg = request.app.state.cfg
    db_path = f"{cfg.headscale_data_path}/db.sqlite"

    ipv4 = ipv4.strip()
    ipv6 = ipv6.strip()

    def err(msg: str):
        from urllib.parse import quote_plus

        return RedirectResponse(
            f"/nodes/{node_id}?error={quote_plus(msg)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if not ipv4 and not ipv6:
        return err("At least one of IPv4 or IPv6 must be provided")

    try:
        v4 = ipaddress.IPv4Address(ipv4) if ipv4 else None
    except ValueError as e:
        return err(f"Invalid IPv4: {e}")
    try:
        v6 = ipaddress.IPv6Address(ipv6) if ipv6 else None
    except ValueError as e:
        return err(f"Invalid IPv6: {e}")

    if v4 and v4 not in ipaddress.IPv4Network(cfg.prefix_v4):
        return err(f"IPv4 {ipv4} is not within configured prefix {cfg.prefix_v4}")
    if v6 and v6 not in ipaddress.IPv6Network(cfg.prefix_v6):
        return err(f"IPv6 {ipv6} is not within configured prefix {cfg.prefix_v6}")

    # Uniqueness check against other nodes in the DB
    try:
        used = list_node_ips(db_path)
    except Exception as e:
        log.exception("could not read headscale db at %s", db_path)
        return err(f"Cannot access Headscale DB: {e}")

    for r in used:
        if str(r["id"]) == str(node_id):
            continue
        if ipv4 and r.get("ipv4") == ipv4:
            return err(f"IPv4 {ipv4} already used by node {r['id']} ({r.get('given_name', '?')})")
        if ipv6 and r.get("ipv6") == ipv6:
            return err(f"IPv6 {ipv6} already used by node {r['id']} ({r.get('given_name', '?')})")

    try:
        update_node_ips(db_path, int(node_id), ipv4 or None, ipv6 or None)
    except Exception as e:
        log.exception("DB update failed")
        return err(f"DB update failed: {e}")

    log.info("IPs updated for node %s: ipv4=%s ipv6=%s; restarting headscale", node_id, ipv4, ipv6)

    try:
        restart_headscale(cfg.headscale_container)
    except Exception as e:
        log.exception("headscale restart failed")
        return err(f"DB updated but Headscale restart failed: {str(e)[:120]}. You may need to restart manually.")

    # Wait for Headscale to come back up so the redirect lands on a working page.
    health_url = f"{cfg.headscale_url.rstrip('/')}/health"
    ready = wait_until_responsive(health_url, attempts=30, interval=0.5)
    if not ready:
        log.warning("Headscale did not become responsive within 15s after restart")

    from urllib.parse import quote_plus

    msg = "IPs updated — Headscale restarted" if ready else "IPs updated — Headscale still starting, refresh in a moment"
    return RedirectResponse(
        f"/nodes/{node_id}?flash={quote_plus(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/nodes/{node_id}/routes")
async def update_routes(
    request: Request,
    node_id: str,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse(f"/nodes/{node_id}", status_code=status.HTTP_303_SEE_OTHER)

    form = await request.form()
    enabled_subnets = form.getlist("subnet")
    exit_on = form.get("exit_node") in ("on", "true", "1")

    routes: list[str] = [s for s in enabled_subnets if s]
    if exit_on:
        routes.extend(["0.0.0.0/0", "::/0"])

    # Headscale 0.28 bug: approve_routes API returns success for empty lists but
    # doesn't actually persist, so old approved routes survive a restart. Bypass
    # via direct DB write + container restart when clearing all routes.
    if not routes:
        cfg = request.app.state.cfg
        db_path = f"{cfg.headscale_data_path}/db.sqlite"
        try:
            clear_node_approved_routes(db_path, int(node_id))
        except Exception as e:
            log.exception("clear_node_approved_routes failed")
            return RedirectResponse(
                f"/nodes/{node_id}?error={_format_error_msg('DB write failed', e)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        try:
            restart_headscale(cfg.headscale_container)
        except Exception as e:
            log.exception("headscale restart failed")
            return RedirectResponse(
                f"/nodes/{node_id}?error={_format_error_msg('DB updated but Headscale restart failed', e)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        wait_until_responsive(f"{cfg.headscale_url.rstrip('/')}/health", attempts=30, interval=0.5)
        return RedirectResponse(
            f"/nodes/{node_id}?flash=All+routes+cleared+%E2%80%94+Headscale+restarted",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        hs.set_approved_routes(node_id, routes)
    except httpx.HTTPStatusError as e:
        return RedirectResponse(
            f"/nodes/{node_id}?error={_format_error(e, 'Could not update routes')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(f"/nodes/{node_id}?flash=Routes+updated", status_code=status.HTTP_303_SEE_OTHER)


def _normalize_tag(name: str) -> str:
    name = name.strip()
    if not name:
        return ""
    return name if name.startswith("tag:") else f"tag:{name}"


@router.post("/nodes/{node_id}/tags/add")
def add_tag(
    request: Request,
    node_id: str,
    tag: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse(f"/nodes/{node_id}", status_code=status.HTTP_303_SEE_OTHER)

    new_tag = _normalize_tag(tag)
    if not new_tag:
        return RedirectResponse(f"/nodes/{node_id}", status_code=status.HTTP_303_SEE_OTHER)

    try:
        node = hs.get_node(node_id)
        existing = list(node.get("tags") or [])
    except httpx.HTTPError as e:
        return RedirectResponse(
            f"/nodes/{node_id}?error={_format_error_msg('Could not read node', e)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if new_tag in existing:
        return RedirectResponse(f"/nodes/{node_id}?flash=Tag+already+set", status_code=status.HTTP_303_SEE_OTHER)
    existing.append(new_tag)

    try:
        hs.set_tags(node_id, existing)
    except httpx.HTTPStatusError as e:
        return RedirectResponse(
            f"/nodes/{node_id}?error={_format_error(e, 'Could not add tag')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(f"/nodes/{node_id}?flash=Tag+added", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/nodes/{node_id}/tags/remove")
def remove_tag(
    request: Request,
    node_id: str,
    tag: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse(f"/nodes/{node_id}", status_code=status.HTTP_303_SEE_OTHER)

    target = _normalize_tag(tag)

    try:
        node = hs.get_node(node_id)
        existing = list(node.get("tags") or [])
    except httpx.HTTPError as e:
        return RedirectResponse(
            f"/nodes/{node_id}?error={_format_error_msg('Could not read node', e)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    new_list = [t for t in existing if t != target]
    if new_list == existing:
        return RedirectResponse(f"/nodes/{node_id}", status_code=status.HTTP_303_SEE_OTHER)

    # Headscale's API rejects empty tag lists ("must have at least one tag").
    # Bypass via direct DB write + container restart when removing the last tag.
    if not new_list:
        cfg = request.app.state.cfg
        db_path = f"{cfg.headscale_data_path}/db.sqlite"
        try:
            clear_node_tags(db_path, int(node_id))
        except Exception as e:
            log.exception("clear_node_tags failed")
            return RedirectResponse(
                f"/nodes/{node_id}?error={_format_error_msg('DB write failed', e)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        try:
            restart_headscale(cfg.headscale_container)
        except Exception as e:
            log.exception("headscale restart failed")
            return RedirectResponse(
                f"/nodes/{node_id}?error={_format_error_msg('DB updated but Headscale restart failed', e)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        wait_until_responsive(f"{cfg.headscale_url.rstrip('/')}/health", attempts=30, interval=0.5)
        return RedirectResponse(
            f"/nodes/{node_id}?flash=Last+tag+removed+%E2%80%94+Headscale+restarted",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        hs.set_tags(node_id, new_list)
    except httpx.HTTPStatusError as e:
        return RedirectResponse(
            f"/nodes/{node_id}?error={_format_error(e, 'Could not remove tag')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(f"/nodes/{node_id}?flash=Tag+removed", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/nodes/{node_id}/user")
def change_user(
    request: Request,
    node_id: str,
    user_id: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    """Direct-DB bypass: Headscale 0.28 has no API for changing a node's user."""
    cfg = request.app.state.cfg
    hs = request.app.state.hs
    db_path = f"{cfg.headscale_data_path}/db.sqlite"

    from urllib.parse import quote_plus

    def err(msg: str):
        return RedirectResponse(
            f"/nodes/{node_id}?error={quote_plus(msg)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Validate user exists.
    try:
        users = hs.list_users() if hs else []
    except httpx.HTTPError as e:
        return err(f"Could not list users: {e}")
    user = next((u for u in users if str(u.get("id")) == str(user_id)), None)
    if not user:
        return err(f"User {user_id} not found")

    try:
        update_node_user(db_path, int(node_id), int(user_id))
    except Exception as e:
        log.exception("update_node_user failed")
        return err(f"DB update failed: {e}")
    log.info("Node %s reassigned to user %s (%s)", node_id, user_id, user.get("name"))

    try:
        restart_headscale(cfg.headscale_container)
    except Exception as e:
        log.exception("headscale restart failed")
        return err(f"DB updated but Headscale restart failed: {str(e)[:120]}")

    health_url = f"{cfg.headscale_url.rstrip('/')}/health"
    ready = wait_until_responsive(health_url, attempts=30, interval=0.5)
    msg = f"User changed to {user.get('name')}" + ("" if ready else " — Headscale still starting")
    return RedirectResponse(
        f"/nodes/{node_id}?flash={quote_plus(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _format_error_msg(prefix: str, e: Exception) -> str:
    from urllib.parse import quote_plus

    return quote_plus(f"{prefix}: {str(e)[:120]}")


def _format_error(e: httpx.HTTPStatusError, prefix: str) -> str:
    detail = ""
    try:
        body = e.response.json()
        detail = body.get("message") or body.get("error") or ""
    except Exception:
        detail = e.response.text[:200]
    return f"{prefix}: {detail}".strip().replace(" ", "+")


@router.post("/nodes/{node_id}/expire")
def expire_node(
    request: Request,
    node_id: str,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/nodes", status_code=status.HTTP_303_SEE_OTHER)
    name = _resolve_name(hs, node_id)
    try:
        hs.expire_node(node_id)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, f"Expire of '{name}' failed")
    return RedirectResponse(f"/nodes?expired={name}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/nodes/{node_id}/delete")
def delete_node(
    request: Request,
    node_id: str,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/nodes", status_code=status.HTTP_303_SEE_OTHER)
    name = _resolve_name(hs, node_id)
    try:
        hs.delete_node(node_id)
    except httpx.HTTPStatusError as e:
        return _render_error(request, sess, hs, e, f"Delete of '{name}' failed")
    return RedirectResponse(f"/nodes?deleted={name}", status_code=status.HTTP_303_SEE_OTHER)


def _resolve_name(hs, node_id: str) -> str:
    try:
        for n in hs.list_nodes():
            if str(n.get("id")) == str(node_id):
                return n.get("givenName") or n.get("name") or node_id
    except httpx.HTTPError:
        pass
    return node_id


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
        nodes = _decorate(hs.list_nodes())
        users = hs.list_users()
    except httpx.HTTPError:
        nodes, users = [], []
    return templates.TemplateResponse(
        request,
        "nodes.html",
        {
            "username": sess["username"],
            "nodes": nodes,
            "users": users,
            "error": msg,
            "renamed": None,
            "expired": None,
            "deleted": None,
            "registered": None,
        },
        status_code=400,
    )
