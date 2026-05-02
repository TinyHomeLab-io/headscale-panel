"""Firewall-style ACL policy editor for Headscale."""
import ipaddress
import json
import logging
from urllib.parse import quote_plus

import httpx
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.policy")

DEFAULT_POLICY: dict = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}


def _load(hs) -> dict:
    raw = hs.get_policy()
    s = raw.get("policy", "") if raw else ""
    if not s.strip():
        return dict(DEFAULT_POLICY)
    try:
        return json.loads(s)
    except json.JSONDecodeError as e:
        log.warning("policy is not valid JSON (hujson with comments?): %s", e)
        # Best-effort: strip line comments and try again
        cleaned = "\n".join(
            line for line in s.splitlines() if not line.strip().startswith("//")
        )
        return json.loads(cleaned)


def _save(hs, doc: dict) -> None:
    hs.set_policy(json.dumps(doc, indent=2))


def _split_dst(dst: str) -> tuple[str, str]:
    """Split 'alias:ports' into (alias, ports). Handles 'tag:server:22' correctly."""
    idx = dst.rfind(":")
    if idx < 0:
        return dst, "*"
    port = dst[idx + 1 :]
    # Port spec characters: digits, ranges (-), comma, *
    if port == "*" or all(c.isdigit() or c in "-," for c in port):
        return dst[:idx], port
    return dst, "*"


def _split_list(s: str) -> list[str]:
    return [x.strip() for x in s.replace(",", " ").split() if x.strip()]


def _port_in_spec(query_port: int, spec: str) -> bool:
    """Match a single port number against a spec like '*', '22', '80,443', '1000-2000'."""
    spec = (spec or "").strip()
    if spec == "*":
        return True
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                if int(a) <= query_port <= int(b):
                    return True
            except ValueError:
                continue
        elif part.isdigit() and int(part) == query_port:
            return True
    return False


def _build_resolvers(nodes: list[dict]) -> dict:
    """Compute identity-expansion maps from current node state.

    user_ips:  "user1@" -> {ips of user1's UNTAGGED nodes}
    tag_ips:   "tag:server" -> {ips of nodes carrying tag:server}
    ip_ident:  "100.64.0.1" -> ("user","user1@") or ("tag","tag:server")
    """
    user_ips: dict[str, set[str]] = {}
    tag_ips: dict[str, set[str]] = {}
    ip_ident: dict[str, tuple[str, str]] = {}

    for n in nodes:
        ips = n.get("ipAddresses") or []
        tags = n.get("tags") or []
        user = (n.get("user") or {}).get("name", "")
        user_alias = f"{user}@" if user else ""

        if tags:
            for tag in tags:
                tag_ips.setdefault(tag, set()).update(ips)
            primary = tags[0]
            for ip in ips:
                ip_ident[ip] = ("tag", primary)
        elif user_alias:
            user_ips.setdefault(user_alias, set()).update(ips)
            for ip in ips:
                ip_ident[ip] = ("user", user_alias)

    return {"user_ips": user_ips, "tag_ips": tag_ips, "ip_ident": ip_ident}


def _query_to_ips(query: str, res: dict) -> set[str]:
    """Resolve a query (user@, tag:X, IP) to the IP set it represents."""
    if query.startswith("tag:"):
        return set(res["tag_ips"].get(query, set()))
    if query.endswith("@"):
        return set(res["user_ips"].get(query, set()))
    try:
        ipaddress.ip_address(query)
        return {query}
    except ValueError:
        return set()


def _entry_matches_query(
    entry: str, query: str, doc: dict, res: dict, *, depth: int = 0
) -> bool:
    """Does a rule src/dst alias `entry` cover the test `query`?"""
    if depth > 5:
        return False  # cycle guard for groups
    if entry == "*":
        return True
    if entry == query:
        return True

    # Group: recurse into members
    if entry.startswith("group:"):
        for m in (doc.get("groups") or {}).get(entry, []):
            if _entry_matches_query(m, query, doc, res, depth=depth + 1):
                return True
        return False

    query_ips = _query_to_ips(query, res)

    # Entry is a user — match if any query IP belongs to that user's untagged nodes
    if entry.endswith("@"):
        entry_ips = res["user_ips"].get(entry, set())
        return bool(query_ips & entry_ips)

    # Entry is a tag — match if any query IP is on a node carrying that tag
    if entry.startswith("tag:"):
        entry_ips = res["tag_ips"].get(entry, set())
        return bool(query_ips & entry_ips)

    # Entry is a named host
    hosts = doc.get("hosts") or {}
    if entry in hosts:
        return hosts[entry] in query_ips

    # Entry is a CIDR or IP
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    for qip in query_ips:
        try:
            ip = ipaddress.ip_address(qip)
            if ip.version == net.version and ip in net:
                return True
        except ValueError:
            continue
    return False


def _src_matches(
    src_query: str, rule_src: list[str], doc: dict, res: dict
) -> str | None:
    for entry in rule_src:
        if _entry_matches_query(entry, src_query, doc, res):
            return entry
    return None


def _dst_matches(
    dst_query: str,
    port_query: int | None,
    rule: dict,
    doc: dict,
    res: dict,
) -> tuple[str | None, str | None]:
    for entry in rule.get("dst", []):
        alias, port_spec = _split_dst(entry)

        if port_query is None:
            port_ok = port_spec == "*"
        else:
            port_ok = _port_in_spec(port_query, port_spec)
        if not port_ok:
            continue

        if _entry_matches_query(alias, dst_query, doc, res):
            return entry, port_spec
    return None, None


def _evaluate_policy(
    doc: dict,
    nodes: list[dict],
    src: str,
    dst: str,
    proto: str,
    port: int | None,
) -> dict:
    res = _build_resolvers(nodes)
    rules = doc.get("acls") or []
    for i, rule in enumerate(rules):
        rule_proto = (rule.get("proto") or "").lower()
        if rule_proto and rule_proto != "*" and rule_proto != proto:
            continue
        if not rule_proto and proto not in ("tcp", "udp", "icmp"):
            continue

        matched_src = _src_matches(src, rule.get("src") or [], doc, res)
        if matched_src is None:
            continue
        matched_dst, matched_port = _dst_matches(dst, port, rule, doc, res)
        if matched_dst is None:
            continue

        return {
            "action": rule.get("action", "accept"),
            "rule_index": i,
            "matched_src": matched_src,
            "matched_dst": matched_dst,
            "matched_port_spec": matched_port,
        }
    return {"action": "deny", "rule_index": None}


def _alias_options(doc: dict, users: list[dict]) -> list[dict]:
    """Build dropdown suggestions for source/destination aliases."""
    opts: list[dict] = [{"value": "*", "label": "* (any)"}]
    for u in users:
        name = u.get("name", "")
        if name:
            opts.append({"value": f"{name}@", "label": f"{name}@ (user)"})
    for g in (doc.get("groups") or {}).keys():
        opts.append({"value": g, "label": f"{g} (group)"})
    for t in (doc.get("tagOwners") or {}).keys():
        opts.append({"value": t, "label": f"{t} (tag)"})
    for h in (doc.get("hosts") or {}).keys():
        opts.append({"value": h, "label": f"{h} (host)"})
    return opts


@router.get("/policy")
def view_policy(request: Request, sess: dict = Depends(require_authenticated)):
    hs = request.app.state.hs
    error = None
    doc: dict = dict(DEFAULT_POLICY)
    users: list[dict] = []
    if not hs:
        error = "Headscale client not configured"
    else:
        try:
            doc = _load(hs)
            users = hs.list_users()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            error = f"Could not load policy: {e}"

    rules = []
    for i, r in enumerate(doc.get("acls") or []):
        dsts = []
        port_specs = set()
        for d in r.get("dst", []):
            alias, port = _split_dst(d)
            dsts.append({"alias": alias, "port": port})
            port_specs.add(port)
        rules.append(
            {
                "i": i,
                "action": r.get("action", "accept"),
                "src": r.get("src", []),
                "dsts": dsts,
                "proto": r.get("proto", ""),  # empty = "any" (TCP+UDP+ICMP)
                "port_summary": ", ".join(sorted(port_specs)) if port_specs else "*",
            }
        )

    tag_owners = doc.get("tagOwners") or {}

    highlight_str = request.query_params.get("highlight", "")
    highlight_index = int(highlight_str) if highlight_str.isdigit() else None

    return templates.TemplateResponse(
        request,
        "policy.html",
        {
            "username": sess["username"],
            "rules": rules,
            "tag_owners": tag_owners,
            "users": users,
            "alias_options": _alias_options(doc, users),
            "error": error,
            "flash": request.query_params.get("flash"),
            "save_error": request.query_params.get("save_error"),
            "highlight_index": highlight_index,
        },
    )


VALID_PROTOS = {"tcp", "udp", "icmp", "icmpv6", "sctp", "igmp", "gre", "esp", "ah"}


@router.post("/policy/rules/add")
def add_rule(
    request: Request,
    action: str = Form("accept"),
    src: str = Form(...),
    dst: str = Form(...),
    proto: str = Form(""),
    ports: str = Form("*"),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)

    src_list = _split_list(src)
    dst_aliases = _split_list(dst)
    port_spec = ports.strip() or "*"
    proto = proto.strip().lower()
    if not src_list or not dst_aliases:
        return RedirectResponse(
            f"/policy?save_error={quote_plus('Source and destination are required')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # Protocols that don't carry ports should always use ":*"
    portless = {"icmp", "icmpv6", "igmp", "esp", "ah", "gre"}
    if proto in portless:
        port_spec = "*"

    dst_list = []
    for d in dst_aliases:
        # Don't double-append a port if user already typed alias:port
        _existing_alias, existing_port = _split_dst(d)
        if existing_port != "*" or d.endswith(":*"):
            dst_list.append(d)
        else:
            dst_list.append(f"{d}:{port_spec}")

    try:
        doc = _load(hs)
        rules = doc.get("acls") or []
        rule = {
            "action": action if action in ("accept", "drop") else "accept",
            "src": src_list,
            "dst": dst_list,
        }
        if proto and proto in VALID_PROTOS:
            rule["proto"] = proto
        rules.append(rule)
        doc["acls"] = rules
        _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return RedirectResponse("/policy?flash=Rule+added", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/policy/rules/reorder")
async def reorder_rules(
    request: Request,
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    form = await request.form()
    order_str = (form.get("order") or "").strip()
    try:
        indices = [int(i) for i in order_str.split(",") if i.strip().isdigit()]
    except ValueError:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)

    try:
        doc = _load(hs)
        rules = doc.get("acls") or []
        # Validate: must be a permutation of 0..len(rules)-1
        if sorted(indices) != list(range(len(rules))):
            return RedirectResponse(
                f"/policy?save_error={quote_plus('Invalid reorder: indices do not match rules')}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        new_rules = [rules[i] for i in indices]
        if new_rules == rules:
            return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
        doc["acls"] = new_rules
        _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse("/policy?flash=Rules+reordered", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/policy/rules/move")
def move_rule(
    request: Request,
    index: int = Form(...),
    direction: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    try:
        doc = _load(hs)
        rules = doc.get("acls") or []
        if direction == "up" and 0 < index < len(rules):
            rules[index - 1], rules[index] = rules[index], rules[index - 1]
        elif direction == "down" and 0 <= index < len(rules) - 1:
            rules[index + 1], rules[index] = rules[index], rules[index + 1]
        else:
            return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
        doc["acls"] = rules
        _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse("/policy?flash=Rule+moved", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/policy/rules/delete")
def delete_rule(
    request: Request,
    index: int = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    try:
        doc = _load(hs)
        rules = doc.get("acls") or []
        if 0 <= index < len(rules):
            rules.pop(index)
            doc["acls"] = rules
            _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse("/policy?flash=Rule+removed", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/policy/tagowners/add")
def add_tag_owner(
    request: Request,
    tag: str = Form(...),
    owners: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)

    tag = tag.strip()
    if not tag.startswith("tag:"):
        tag = "tag:" + tag
    owner_list = _split_list(owners)
    if not owner_list:
        return RedirectResponse(
            f"/policy?save_error={quote_plus('At least one owner required')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        doc = _load(hs)
        existing = doc.get("tagOwners") or {}
        existing[tag] = sorted(set(existing.get(tag, []) + owner_list))
        doc["tagOwners"] = existing
        _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        f"/policy?flash=Tag+{quote_plus(tag)}+added", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/policy/tagowners/owner/add")
def add_one_owner(
    request: Request,
    tag: str = Form(...),
    owner: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    owner = owner.strip()
    if not owner:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    try:
        doc = _load(hs)
        existing = doc.get("tagOwners") or {}
        if tag not in existing:
            return RedirectResponse(
                f"/policy?save_error={quote_plus(f'Tag {tag} does not exist')}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        if owner not in existing[tag]:
            existing[tag].append(owner)
            doc["tagOwners"] = existing
            _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        f"/policy?flash=Owner+added+to+{quote_plus(tag)}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/policy/tagowners/owner/remove")
def remove_one_owner(
    request: Request,
    tag: str = Form(...),
    owner: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    try:
        doc = _load(hs)
        existing = doc.get("tagOwners") or {}
        if tag in existing:
            new_owners = [o for o in existing[tag] if o != owner]
            if not new_owners:
                return RedirectResponse(
                    f"/policy?save_error={quote_plus('Cannot remove the last owner — delete the tag instead')}",
                    status_code=status.HTTP_303_SEE_OTHER,
                )
            existing[tag] = new_owners
            doc["tagOwners"] = existing
            _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        f"/policy?flash=Owner+removed+from+{quote_plus(tag)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/policy/tagowners/remove")
def remove_tag_owner(
    request: Request,
    tag: str = Form(...),
    sess: dict = Depends(require_authenticated),
):
    hs = request.app.state.hs
    if not hs:
        return RedirectResponse("/policy", status_code=status.HTTP_303_SEE_OTHER)
    try:
        doc = _load(hs)
        existing = doc.get("tagOwners") or {}
        existing.pop(tag, None)
        doc["tagOwners"] = existing
        _save(hs, doc)
    except (httpx.HTTPError, json.JSONDecodeError) as e:
        return RedirectResponse(
            f"/policy?save_error={quote_plus(_format_save_error(e))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        f"/policy?flash=Tag+{quote_plus(tag)}+removed", status_code=status.HTTP_303_SEE_OTHER
    )


def _format_save_error(e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError):
        try:
            body = e.response.json()
            msg = body.get("message") or body.get("error") or e.response.text[:200]
        except Exception:
            msg = e.response.text[:200]
        return f"Headscale rejected the policy: {msg}"
    return f"Could not save policy: {e}"
