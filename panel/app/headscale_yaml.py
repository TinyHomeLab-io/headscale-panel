"""Shared helpers for reading/writing Headscale's config.yaml."""
import logging
from pathlib import Path

import yaml

from .headscale_db import restart_headscale, wait_until_responsive

log = logging.getLogger("panel.hs_yaml")


def load_doc(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = yaml.safe_load(p.read_text())
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError as e:
        log.warning("config.yaml parse failed: %s", e)
        return {}


def save_doc(path: str, doc: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(doc, default_flow_style=False, sort_keys=False))


def read_raw(path: str) -> str:
    p = Path(path)
    return p.read_text() if p.exists() else ""


def write_raw(path: str, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def restart_and_wait(headscale_url: str, container_name: str) -> str | None:
    """Restart Headscale and wait for /health. Returns error message or None."""
    try:
        restart_headscale(container_name)
    except Exception as e:
        log.exception("headscale restart failed")
        return f"Saved but Headscale restart failed: {e}"
    health_url = f"{headscale_url.rstrip('/')}/health"
    wait_until_responsive(health_url, attempts=30, interval=0.5)
    return None


def split_lines(s: str) -> list[str]:
    return [line.strip() for line in (s or "").splitlines() if line.strip()]
