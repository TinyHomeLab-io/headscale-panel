import ipaddress
import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.dashboard")

EXIT_ROUTES = {"0.0.0.0/0", "::/0"}


def _online(node: dict) -> bool:
    if "online" in node and isinstance(node["online"], bool):
        return node["online"]
    return False


def _is_exit_node(node: dict) -> bool:
    available = set(node.get("availableRoutes") or [])
    approved = set(node.get("approvedRoutes") or [])
    return bool(EXIT_ROUTES & (available | approved))


def _is_subnet_router(node: dict) -> bool:
    available = set(node.get("availableRoutes") or [])
    approved = set(node.get("approvedRoutes") or [])
    return bool((available | approved) - EXIT_ROUTES)


def _format_int(n: int) -> str:
    if n < 1_000:
        return f"{n}"
    if n < 1_000_000:
        return f"{n:,}"
    if n < 1_000_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n < 1_000_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    # IPv6 ranges produce numbers way bigger than this — fall through to scientific.
    return f"{n:.2e}"


def _format_ipv6_pool(net: "ipaddress.IPv6Network") -> str:
    """IPv6 prefixes have astronomical address counts; show the host-bit width instead."""
    host_bits = 128 - net.prefixlen
    return f"2^{host_bits} (≈ {2 ** host_bits:.1e})"


def _route_lookup(query: str, nodes: list[dict]) -> tuple[list[dict], str]:
    """Find nodes that route the query target.

    Returns (matches, kind) where kind is one of:
      "specific"       — at least one node has a matching/covering route
      "exit_fallback"  — no specific match; traffic would go via an exit node
      "none"           — nothing matches (no exit node either, or invalid query)
    """
    q = (query or "").strip()
    if not q:
        return [], "none"

    target_net: ipaddress._BaseNetwork | None = None
    target_ip: ipaddress._BaseAddress | None = None
    if "/" in q:
        try:
            target_net = ipaddress.ip_network(q, strict=False)
        except ValueError:
            return [], "none"
    else:
        try:
            target_ip = ipaddress.ip_address(q)
        except ValueError:
            return [], "none"

    # Pass 1: nodes with a route that exactly matches or covers the target.
    matches: list[dict] = []
    for n in nodes:
        approved = set(n.get("approvedRoutes") or [])
        advertised = set(n.get("availableRoutes") or [])
        all_routes = approved | advertised
        if not all_routes:
            continue

        node_routes: list[dict] = []
        for route in all_routes:
            try:
                net = ipaddress.ip_network(route)
            except ValueError:
                continue

            if target_net is not None:
                if net.version != target_net.version or net != target_net:
                    continue
                kind = "exact"
            else:
                assert target_ip is not None
                if net.version != target_ip.version or target_ip not in net:
                    continue
                kind = "covers"

            label = "Exit node" if route in ("0.0.0.0/0", "::/0") else route
            node_routes.append(
                {
                    "cidr": route,
                    "label": label,
                    "approved": route in approved,
                    "advertised": route in advertised,
                    "kind": kind,
                }
            )

        if node_routes:
            matches.append({"node": n, "routes": node_routes})

    if matches:
        return matches, "specific"

    # Pass 2: query matches a node's own tailnet IP (or a CIDR covering it).
    ip_matches: list[dict] = []
    for n in nodes:
        hit_ips: list[str] = []
        for ip_str in n.get("ipAddresses") or []:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if target_net is not None:
                if ip.version == target_net.version and ip in target_net:
                    hit_ips.append(ip_str)
            else:
                assert target_ip is not None
                if ip.version == target_ip.version and ip == target_ip:
                    hit_ips.append(ip_str)
        if hit_ips:
            ip_matches.append({"node": n, "ips": hit_ips})
    if ip_matches:
        return ip_matches, "node_ip"

    # Pass 3: fallback to exit nodes for the right family.
    if q in ("0.0.0.0/0", "::/0"):
        return [], "none"  # user queried the default route itself; no matches

    family_default = "0.0.0.0/0"
    if (target_net is not None and target_net.version == 6) or (
        target_ip is not None and target_ip.version == 6
    ):
        family_default = "::/0"

    fallback: list[dict] = []
    for n in nodes:
        approved = set(n.get("approvedRoutes") or [])
        advertised = set(n.get("availableRoutes") or [])
        if family_default not in approved and family_default not in advertised:
            continue
        fallback.append(
            {
                "node": n,
                "routes": [
                    {
                        "cidr": family_default,
                        "label": "Exit node",
                        "approved": family_default in approved,
                        "advertised": family_default in advertised,
                        "kind": "default",
                    }
                ],
            }
        )

    return fallback, ("exit_fallback" if fallback else "none")


@router.get("/")
def dashboard(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    cfg = request.app.state.cfg

    stats = {
        "users": 0,
        "nodes_total": 0,
        "nodes_online": 0,
        "nodes_offline": 0,
        "exit_nodes": 0,
        "subnet_routers": 0,
        "approved_routes_count": 0,
        "preauth_active": 0,
        "preauth_used": 0,
        "preauth_expired": 0,
        "ipv4_used": 0,
        "ipv4_pool": 0,
        "ipv4_pool_display": "—",
        "ipv6_used": 0,
        "ipv6_pool_display": "—",
    }
    error = None

    # IPv4 pool capacity from configured prefix
    try:
        net4 = ipaddress.IPv4Network(cfg.prefix_v4)
        # Subtract network + broadcast for true usable count, though Tailscale's
        # CGNAT range doesn't really use those. Close enough for a dashboard.
        stats["ipv4_pool"] = max(net4.num_addresses - 2, 0)
        stats["ipv4_pool_display"] = _format_int(stats["ipv4_pool"])
    except ValueError:
        pass

    try:
        net6 = ipaddress.IPv6Network(cfg.prefix_v6)
        stats["ipv6_pool_display"] = _format_ipv6_pool(net6)
    except ValueError:
        pass

    if hs:
        try:
            users = hs.list_users()
            nodes = hs.list_nodes()
            stats["users"] = len(users)
            stats["nodes_total"] = len(nodes)

            for n in nodes:
                if _online(n):
                    stats["nodes_online"] += 1
                if _is_exit_node(n):
                    stats["exit_nodes"] += 1
                if _is_subnet_router(n):
                    stats["subnet_routers"] += 1
                stats["approved_routes_count"] += len(n.get("approvedRoutes") or [])
                # IP usage counts (a node may have one or both)
                ips = n.get("ipAddresses") or []
                if any("." in ip for ip in ips):
                    stats["ipv4_used"] += 1
                if any(":" in ip for ip in ips):
                    stats["ipv6_used"] += 1
            stats["nodes_offline"] = stats["nodes_total"] - stats["nodes_online"]

            # Preauth keys (Headscale 0.28 list ignores user filter; one call gets all).
            try:
                preauth = hs.list_preauthkeys(users[0]["id"]) if users else []
            except httpx.HTTPError:
                preauth = []
            seen: set[str] = set()
            now = datetime.now(timezone.utc)
            for k in preauth:
                kid = str(k.get("id"))
                if kid in seen:
                    continue
                seen.add(kid)
                exp = k.get("expiration") or ""
                expired = False
                if exp and not exp.startswith("0001-01-01"):
                    try:
                        expired = datetime.fromisoformat(exp.replace("Z", "+00:00")) < now
                    except ValueError:
                        pass
                if k.get("used"):
                    stats["preauth_used"] += 1
                elif expired:
                    stats["preauth_expired"] += 1
                else:
                    stats["preauth_active"] += 1
        except httpx.HTTPError as e:
            log.warning("dashboard fetch failed: %s", e)
            error = "Headscale unreachable — check Headscale is running"

    # Recent activity (sort the nodes we already fetched above)
    recent_nodes: list[dict] = []
    if hs and not error:
        try:
            recent_nodes = sorted(
                hs.list_nodes(),
                key=lambda n: n.get("lastSeen") or "",
                reverse=True,
            )[:5]
        except httpx.HTTPError:
            pass

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": sess["username"],
            "stats": stats,
            "error": error,
            "recent_nodes": recent_nodes,
            "prefix_v4": cfg.prefix_v4,
            "prefix_v6": cfg.prefix_v6,
        },
    )
