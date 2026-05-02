"""Direct SQLite operations against Headscale's db.sqlite.

Used only for operations Headscale's API does not expose (IP edit, change user, etc.).
After a write, Headscale must be restarted to pick up the change because it caches
state in memory.
"""
import logging
import sqlite3
from contextlib import contextmanager

log = logging.getLogger("panel.hs_db")


@contextmanager
def hs_connect(db_path: str):
    con = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
    finally:
        con.close()


def list_node_ips(db_path: str) -> list[dict]:
    with hs_connect(db_path) as c:
        return [dict(r) for r in c.execute(
            "SELECT id, given_name, ipv4, ipv6 FROM nodes WHERE deleted_at IS NULL"
        )]


def update_node_ips(
    db_path: str,
    node_id: int,
    ipv4: str | None,
    ipv6: str | None,
) -> None:
    with hs_connect(db_path) as c:
        c.execute(
            "UPDATE nodes SET ipv4=?, ipv6=?, updated_at=datetime('now') WHERE id=?",
            (ipv4 if ipv4 else None, ipv6 if ipv6 else None, node_id),
        )


def update_node_user(db_path: str, node_id: int, user_id: int) -> None:
    with hs_connect(db_path) as c:
        c.execute(
            "UPDATE nodes SET user_id=?, updated_at=datetime('now') WHERE id=?",
            (user_id, node_id),
        )


def clear_node_tags(db_path: str, node_id: int) -> None:
    """Clear all tags from a node — Headscale's API rejects empty tag lists, so this bypasses."""
    with hs_connect(db_path) as c:
        c.execute(
            "UPDATE nodes SET tags='[]', updated_at=datetime('now') WHERE id=?",
            (node_id,),
        )


def clear_node_approved_routes(db_path: str, node_id: int) -> None:
    """Clear all approved routes — Headscale's approve_routes API returns success for
    empty lists but doesn't actually persist, so direct DB write is needed."""
    with hs_connect(db_path) as c:
        c.execute(
            "UPDATE nodes SET approved_routes='[]', updated_at=datetime('now') WHERE id=?",
            (node_id,),
        )


def restart_headscale(container_name: str, timeout: int = 15) -> None:
    """Restart the Headscale container so it picks up direct-DB mutations."""
    import docker  # imported lazily so panel still works without docker SDK in non-bypass paths

    client = docker.from_env()
    container = client.containers.get(container_name)
    container.restart(timeout=timeout)
    log.info("restarted Headscale container %s", container_name)


def wait_until_responsive(url: str, attempts: int = 25, interval: float = 0.5) -> bool:
    """Poll url until it returns 2xx or attempts run out."""
    import time

    import httpx

    for _ in range(attempts):
        try:
            r = httpx.get(url, timeout=2.0)
            if 200 <= r.status_code < 300:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(interval)
    return False
