from typing import Any

import httpx


class HeadscaleClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        if not api_key:
            raise RuntimeError("PANEL_HEADSCALE_API_KEY is empty")
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    # --- Users ---
    def list_users(self) -> list[dict[str, Any]]:
        r = self._client.get("/api/v1/user")
        r.raise_for_status()
        return r.json().get("users", []) or []

    def create_user(self, name: str) -> dict[str, Any]:
        r = self._client.post("/api/v1/user", json={"name": name})
        r.raise_for_status()
        return r.json().get("user", {})

    def delete_user(self, user_id: str | int) -> None:
        r = self._client.delete(f"/api/v1/user/{user_id}")
        r.raise_for_status()

    def rename_user(self, user_id: str | int, new_name: str) -> dict[str, Any]:
        r = self._client.post(f"/api/v1/user/{user_id}/rename/{new_name}")
        r.raise_for_status()
        return r.json().get("user", {})

    # --- Nodes ---
    def list_nodes(self) -> list[dict[str, Any]]:
        r = self._client.get("/api/v1/node")
        r.raise_for_status()
        return r.json().get("nodes", []) or []

    def get_node(self, node_id: str | int) -> dict[str, Any]:
        r = self._client.get(f"/api/v1/node/{node_id}")
        r.raise_for_status()
        return r.json().get("node", {})

    def set_approved_routes(self, node_id: str | int, routes: list[str]) -> dict[str, Any]:
        r = self._client.post(
            f"/api/v1/node/{node_id}/approve_routes",
            json={"routes": routes},
        )
        r.raise_for_status()
        return r.json().get("node", {})

    def set_tags(self, node_id: str | int, tags: list[str]) -> dict[str, Any]:
        r = self._client.post(
            f"/api/v1/node/{node_id}/tags",
            json={"tags": tags},
        )
        r.raise_for_status()
        return r.json().get("node", {})

    # --- Policy ---
    def get_policy(self) -> dict[str, Any]:
        r = self._client.get("/api/v1/policy")
        r.raise_for_status()
        return r.json()

    def set_policy(self, policy_json: str) -> None:
        r = self._client.put("/api/v1/policy", json={"policy": policy_json})
        r.raise_for_status()

    def delete_node(self, node_id: str | int) -> None:
        r = self._client.delete(f"/api/v1/node/{node_id}")
        r.raise_for_status()

    def expire_node(self, node_id: str | int) -> None:
        r = self._client.post(f"/api/v1/node/{node_id}/expire")
        r.raise_for_status()

    def rename_node(self, node_id: str | int, new_name: str) -> None:
        r = self._client.post(f"/api/v1/node/{node_id}/rename/{new_name}")
        r.raise_for_status()

    def register_node(self, username: str, node_key: str) -> dict[str, Any]:
        # Headscale 0.28: this endpoint takes username (not ID) — asymmetric with preauthkey.
        r = self._client.post(
            "/api/v1/node/register",
            params={"user": username, "key": node_key},
        )
        r.raise_for_status()
        return r.json().get("node", {})

    # --- Preauth keys ---
    def list_preauthkeys(self, user_id: str | int) -> list[dict[str, Any]]:
        r = self._client.get("/api/v1/preauthkey", params={"user": str(user_id)})
        r.raise_for_status()
        return r.json().get("preAuthKeys", []) or []

    def create_preauthkey(
        self,
        user_id: str,
        expiration: str | None = None,
        reusable: bool = False,
        ephemeral: bool = False,
        acl_tags: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "user": str(user_id),
            "reusable": reusable,
            "ephemeral": ephemeral,
            "aclTags": acl_tags or [],
        }
        if expiration:
            body["expiration"] = expiration
        r = self._client.post("/api/v1/preauthkey", json=body)
        r.raise_for_status()
        return r.json().get("preAuthKey", {})

    def expire_preauthkey(self, key_id: str | int) -> None:
        # Headscale 0.28: body is {"id": "<id>"}, NOT {user, key} (which 200s silently).
        r = self._client.post(
            "/api/v1/preauthkey/expire",
            json={"id": str(key_id)},
        )
        r.raise_for_status()

    def delete_preauthkey(self, key_id: str | int) -> None:
        # Headscale 0.28: DELETE takes ?id=<id>, NOT a body with user+key.
        # The body-based variant returns 200 silently doing nothing.
        r = self._client.delete("/api/v1/preauthkey", params={"id": str(key_id)})
        r.raise_for_status()
