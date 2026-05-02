"""DNS settings — manages the dns: section of Headscale's config.yaml."""
import logging
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import require_authenticated
from ..headscale_yaml import load_doc, restart_and_wait, save_doc, split_lines

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
log = logging.getLogger("panel.dns")


def _record_target_options(nodes: list[dict]) -> dict:
    """Autocomplete options keyed by record type. Headscale only supports A/AAAA
    in extra_records (CNAME and wildcards are silently dropped by Tailscale's
    DNS map protocol)."""
    a, aaaa = [], []
    for n in nodes or []:
        name = n.get("givenName") or n.get("name", "")
        for ip in n.get("ipAddresses") or []:
            if "." in ip and ":" not in ip:
                a.append({"value": ip, "label": f"{name} ({ip})"})
            elif ":" in ip:
                aaaa.append({"value": ip, "label": f"{name} ({ip})"})
    return {"A": a, "AAAA": aaaa}


@router.get("/dns")
def view_dns(request: Request, sess: dict = Depends(require_authenticated)):
    cfg = request.app.state.cfg
    doc = load_doc(cfg.headscale_config_path)
    dns = doc.get("dns") or {}
    nameservers = dns.get("nameservers") or {}
    extra_records = dns.get("extra_records") or []
    base_domain = dns.get("base_domain", "")

    nodes: list[dict] = []
    hs = request.app.state.hs
    if hs:
        try:
            nodes = hs.list_nodes()
        except Exception:
            log.warning("could not load nodes for record autocomplete", exc_info=True)

    inert_record_types = sorted({
        (r.get("type") or "").upper()
        for r in extra_records
        if (r.get("type") or "").upper() not in {"A", "AAAA"}
    } - {""})

    return templates.TemplateResponse(
        request,
        "dns.html",
        {
            "username": sess["username"],
            "magic_dns": dns.get("magic_dns", True),
            "base_domain": base_domain,
            "override_local_dns": dns.get("override_local_dns", False),
            "global_nameservers": nameservers.get("global") or [],
            "search_domains": dns.get("search_domains") or [],
            "split_dns": list((nameservers.get("split") or {}).items()),
            "extra_records": extra_records,
            "target_options": _record_target_options(nodes),
            "inert_record_types": inert_record_types,
            "flash": request.query_params.get("flash"),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/dns")
async def save_dns(request: Request, sess: dict = Depends(require_authenticated)):
    cfg = request.app.state.cfg
    form = await request.form()

    magic_dns = form.get("magic_dns") == "on"
    base_domain = (form.get("base_domain") or "").strip()
    override_local_dns = form.get("override_local_dns") == "on"
    global_nameservers = split_lines(form.get("global_nameservers", ""))
    search_domains = split_lines(form.get("search_domains", ""))

    split_dns: dict[str, list[str]] = {}
    for d, s in zip(form.getlist("split_domain"), form.getlist("split_servers")):
        d = (d or "").strip()
        if not d:
            continue
        servers = [x.strip() for x in (s or "").replace(",", " ").split() if x.strip()]
        if servers:
            split_dns[d] = servers

    extra_records: list[dict] = []
    for name, type_, value in zip(
        form.getlist("er_name"), form.getlist("er_type"), form.getlist("er_value")
    ):
        n, t, v = (name or "").strip(), (type_ or "").strip().upper(), (value or "").strip()
        # Headscale's DNS push only supports A/AAAA. Drop other types so they
        # don't sit inertly in config.yaml and confuse anyone reading it.
        if n and v and t in ("A", "AAAA"):
            extra_records.append({"name": n, "type": t, "value": v})

    doc = load_doc(cfg.headscale_config_path)
    dns = doc.get("dns") or {}
    dns["magic_dns"] = magic_dns
    if base_domain:
        dns["base_domain"] = base_domain
    dns["override_local_dns"] = override_local_dns
    dns["search_domains"] = search_domains
    dns["extra_records"] = extra_records

    nameservers = dns.get("nameservers") or {}
    nameservers["global"] = global_nameservers
    if split_dns:
        nameservers["split"] = split_dns
    elif "split" in nameservers:
        nameservers["split"] = {}
    dns["nameservers"] = nameservers
    doc["dns"] = dns

    try:
        save_doc(cfg.headscale_config_path, doc)
    except Exception as e:
        log.exception("config write failed")
        return RedirectResponse(
            f"/dns?error={quote_plus(f'Could not write config: {e}')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    err = restart_and_wait(cfg.headscale_url, cfg.headscale_container)
    if err:
        return RedirectResponse(
            f"/dns?error={quote_plus(err)}", status_code=status.HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        "/dns?flash=DNS+saved+%E2%80%94+Headscale+restarted",
        status_code=status.HTTP_303_SEE_OTHER,
    )
