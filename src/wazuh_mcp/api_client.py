"""Async client for the Wazuh Server API (management plane, default :55000).

Handles the JWT dance: `POST /security/user/authenticate` with basic auth returns
a bearer token that expires (15 minutes by default). We decode the token's `exp`
claim to refresh proactively, and still retry once on a 401 in case the manager
revoked it early (a `PUT /security/config` restart does exactly that).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from typing import Any

import httpx2 as httpx

from .config import ServerApiConfig
from .errors import WazuhAuthError, WazuhError

# Wazuh wraps every response in {"data": {"affected_items": [...], ...}, "error": 0}
AffectedItems = dict[str, Any]


class WazuhAPIClient:
    def __init__(self, config: ServerApiConfig) -> None:
        self._config = config
        self._client = httpx.AsyncClient(
            base_url=config.url,
            verify=config.ca_bundle or config.verify_ssl,
            timeout=config.timeout,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        )
        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._auth_lock = asyncio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---------------------------------------------------------------- auth

    async def _authenticate(self) -> str:
        """Exchange basic auth for a JWT. Callers must hold `_auth_lock`."""
        try:
            response = await self._client.post(
                "/security/user/authenticate",
                auth=(self._config.user, self._config.password),
                params={"raw": "false"},
            )
        except httpx.RequestError as exc:
            raise WazuhError(
                f"Cannot reach the Wazuh Server API at {self._config.url}: {exc}. "
                "Check WAZUH_API_URL, network reachability, and WAZUH_VERIFY_SSL "
                "(Wazuh ships self-signed certificates by default)."
            ) from exc

        if response.status_code in (401, 403):
            raise WazuhAuthError(
                "Wazuh Server API rejected the credentials in WAZUH_API_USER / "
                f"WAZUH_API_PASSWORD (HTTP {response.status_code})."
            )
        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh authentication failed with HTTP {response.status_code}: "
                f"{_short_body(response)}"
            )

        payload = response.json()
        token = payload.get("data", {}).get("token")
        if not token:
            raise WazuhError(f"Wazuh authentication returned no token: {payload!r}")

        self._token = token
        self._token_expires_at = _jwt_expiry(token) or (time.time() + 900.0)
        return token

    async def _ensure_token(self, *, force: bool = False) -> str:
        async with self._auth_lock:
            expired = time.time() >= (self._token_expires_at - self._config.token_leeway)
            if force or self._token is None or expired:
                return await self._authenticate()
            return self._token

    # ------------------------------------------------------------- request

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Perform an authenticated call, retrying once past a revoked token."""
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        token = await self._ensure_token()

        for attempt in (1, 2):
            try:
                response = await self._client.request(
                    method,
                    path,
                    params=clean_params,
                    json=json_body,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.RequestError as exc:
                raise WazuhError(
                    f"Wazuh Server API request {method} {path} failed: {exc}"
                ) from exc

            # The manager can invalidate a token before its `exp`; re-auth once.
            if response.status_code == 401 and attempt == 1:
                token = await self._ensure_token(force=True)
                continue
            return response

        raise AssertionError("unreachable")

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Perform an authenticated call and return the decoded JSON body."""
        response = await self._send(method, path, params=params, json_body=json_body)
        return _decode(response, method, path)

    async def request_text(
        self, method: str, path: str, *, params: dict[str, Any] | None = None
    ) -> str:
        """Return the body verbatim, for endpoints that do not answer in JSON.

        `GET /rules/files/{name}?raw=true` hands back XML, not JSON — putting it
        through `request()` only ever produced "returned a non-JSON body".
        """
        response = await self._send(method, path, params=params)
        _raise_for_status(response, method, path)
        return response.text

    async def get(self, path: str, **params: Any) -> dict[str, Any]:
        return await self.request("GET", path, params=params)

    async def get_text(self, path: str, **params: Any) -> str:
        return await self.request_text("GET", path, params=params)

    async def get_items(self, path: str, **params: Any) -> AffectedItems:
        """GET an endpoint that returns Wazuh's affected_items envelope."""
        body = await self.get(path, **params)
        return _affected(body, path)


def _raise_for_status(response: httpx.Response, method: str, path: str) -> None:
    if response.status_code == 403:
        raise WazuhAuthError(
            f"Wazuh denied {method} {path} (HTTP 403). The API user lacks an RBAC "
            "policy for this resource; grant it in Wazuh > Security > Roles."
        )
    if response.status_code >= 400:
        raise WazuhError(
            f"Wazuh Server API {method} {path} returned HTTP "
            f"{response.status_code}: {_short_body(response)}"
        )


def _decode(response: httpx.Response, method: str, path: str) -> dict[str, Any]:
    _raise_for_status(response, method, path)
    try:
        return response.json()
    except ValueError as exc:
        raise WazuhError(
            f"Wazuh Server API {method} {path} returned a non-JSON body: "
            f"{_short_body(response)}"
        ) from exc


def _affected(body: dict[str, Any], path: str) -> AffectedItems:
    """Unwrap the affected_items envelope, surfacing per-item failures."""
    data = body.get("data")
    if not isinstance(data, dict):
        raise WazuhError(f"Unexpected Wazuh response shape for {path}: {body!r}")

    failed = data.get("failed_items") or []
    if failed and not data.get("affected_items"):
        raise WazuhError(f"Wazuh reported no affected items for {path}: {failed!r}")

    result: AffectedItems = {
        "items": data.get("affected_items", []),
        "total": data.get("total_affected_items", 0),
    }
    if failed:
        result["failed_items"] = failed
    message = data.get("message") or body.get("message")
    if message:
        result["message"] = message
    return result


def _jwt_expiry(token: str) -> float | None:
    """Read the `exp` claim without verifying the signature (the server already did)."""
    try:
        payload_segment = token.split(".")[1]
    except IndexError:
        return None
    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
        claims = json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    exp = claims.get("exp")
    return float(exp) if isinstance(exp, (int, float)) else None


def _short_body(response: httpx.Response, limit: int = 400) -> str:
    text = response.text.strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")
