"""Diagnostics: route lookup + policy test (separate pages)."""
import ipaddress
import json
import logging

import httpx
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated
from .dashboard import _route_lookup
from .policy import _alias_options, _evaluate_policy, _load

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.diagnostics")


@router.get("/diagnostics")
def diagnostics_root():
    return RedirectResponse("/diagnostics/routes", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/diagnostics/routes")
def routes_lookup(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    nodes: list[dict] = []
    error: str | None = None
    if hs:
        try:
            nodes = hs.list_nodes()
        except httpx.HTTPError as e:
            error = f"Could not load nodes: {e}"
    else:
        error = "Headscale client not configured"

    q = (request.query_params.get("q") or "").strip()
    route_matches: list[dict] = []
    lookup_kind = "none"
    lookup_invalid = False
    if q:
        try:
            ipaddress.ip_network(q, strict=False) if "/" in q else ipaddress.ip_address(q)
        except ValueError:
            lookup_invalid = True
        if not lookup_invalid and nodes:
            route_matches, lookup_kind = _route_lookup(q, nodes)

    return templates.TemplateResponse(
        request,
        "diagnostics_routes.html",
        {
            "username": sess["username"],
            "error": error,
            "q": q,
            "route_matches": route_matches,
            "lookup_kind": lookup_kind,
            "lookup_invalid": lookup_invalid,
        },
    )


@router.get("/diagnostics/policy")
def policy_test(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    nodes: list[dict] = []
    users: list[dict] = []
    doc: dict = {"acls": []}
    error: str | None = None
    if hs:
        try:
            nodes = hs.list_nodes()
            users = hs.list_users()
            doc = _load(hs)
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            error = f"Could not load Headscale state: {e}"
    else:
        error = "Headscale client not configured"

    test_src = (request.query_params.get("test_src") or "").strip()
    test_dst = (request.query_params.get("test_dst") or "").strip()
    test_proto = (request.query_params.get("test_proto") or "tcp").strip().lower()
    test_port_str = (request.query_params.get("test_port") or "").strip()
    test_result: dict | None = None
    test_error: str | None = None

    if test_src and test_dst:
        port_int: int | None = None
        if test_port_str:
            if test_port_str.isdigit():
                port_int = int(test_port_str)
            else:
                test_error = f"Port '{test_port_str}' is not a valid number."
        if not test_error:
            try:
                test_result = _evaluate_policy(
                    doc, nodes, test_src, test_dst, test_proto, port_int
                )
            except Exception as e:
                log.exception("policy evaluator failed")
                test_error = f"Evaluator error: {e}"

    return templates.TemplateResponse(
        request,
        "diagnostics_policy.html",
        {
            "username": sess["username"],
            "error": error,
            "alias_options": _alias_options(doc, users),
            "rules_count": len(doc.get("acls") or []),
            "test_src": test_src,
            "test_dst": test_dst,
            "test_proto": test_proto,
            "test_port": test_port_str,
            "test_result": test_result,
            "test_error": test_error,
        },
    )
