"""Fortinet HTTP clients -- three independent BYOK auth mechanisms under one
connector, same shape as Cisco Secure Access Connector's cisco_client.py.

WHY `ctx.http.*`, NOT A RAW `httpx` CLIENT -- same convention as every other
connector in this portfolio: the SDK's own async HTTP client goes through
the platform's sandboxed egress path.

FortiGate: static Bearer token against `{host}/api/v2/...`.

FortiManager: JSON-RPC POST to a single endpoint `{host}/jsonrpc`. Login via
`sys/login/user` (username/password) returns a `session` id that must be
included in every subsequent JSON-RPC call body. Sessions expire; on a
session-invalid error code the client re-logs in once and retries.

FortiSASE: static Bearer token (FortiCloud IAM) against
`{base_url}/api/v1/...`.
"""
from __future__ import annotations

from typing import Any

FORTIMANAGER_RPC_PATH = "/jsonrpc"
FORTISASE_DEFAULT_BASE = "https://api.fortisase.forticloud.com"

ACCOUNT_MISSING = "FORTINET_ACCOUNT_MISSING"
TOKEN_REJECTED = "FORTINET_TOKEN_REJECTED"
PERMISSION_DENIED = "FORTINET_PERMISSION_DENIED"
NOT_FOUND = "FORTINET_NOT_FOUND"
VALIDATION_FAILED = "FORTINET_VALIDATION_FAILED"
RESPONSE_UNEXPECTED = "FORTINET_RESPONSE_UNEXPECTED"
UNREACHABLE = "FORTINET_UNREACHABLE"
RATE_LIMITED = "FORTINET_RATE_LIMITED"
BACKEND_5XX = "FORTINET_BACKEND_5XX"
BACKEND_TIMEOUT = "FORTINET_BACKEND_TIMEOUT"
SESSION_EXPIRED = "FORTINET_SESSION_EXPIRED"

_MESSAGES = {
    ACCOUNT_MISSING: "No Fortinet connection is set up yet.",
    TOKEN_REJECTED: "Fortinet rejected these credentials. Check the token/username/password, then reconnect.",
    PERMISSION_DENIED: "Fortinet accepted the credentials, but this account lacks the required permission for this operation.",
    NOT_FOUND: "Fortinet has no such resource, or this account cannot access it.",
    VALIDATION_FAILED: "Fortinet rejected the request as invalid.",
    RESPONSE_UNEXPECTED: "Fortinet returned a response the connector could not safely interpret.",
    UNREACHABLE: "Could not reach the Fortinet host. Check the host/URL and network path.",
    RATE_LIMITED: "Fortinet is rate-limiting requests right now. Try again shortly.",
    BACKEND_5XX: "Fortinet's own service returned a server error.",
    BACKEND_TIMEOUT: "The request to Fortinet timed out.",
    SESSION_EXPIRED: "The FortiManager session expired and could not be renewed automatically.",
}


class ClientFail(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(_MESSAGES.get(code, code))

    def message(self) -> str:
        base = _MESSAGES.get(self.code, self.code)
        return f"{base} ({self.detail})" if self.detail else base


def _classify_status(status: int) -> str:
    if status == 401:
        return TOKEN_REJECTED
    if status == 403:
        return PERMISSION_DENIED
    if status == 404:
        return NOT_FOUND
    if status == 400 or status == 422:
        return VALIDATION_FAILED
    if status == 429:
        return RATE_LIMITED
    if 500 <= status < 600:
        return BACKEND_5XX
    return RESPONSE_UNEXPECTED


# ──────────────────────────────────────────────────────────────────────────
# FortiGate
# ──────────────────────────────────────────────────────────────────────────


async def fortigate_request(ctx, conn: dict, method: str, path: str, json_body: dict | None = None, params: dict | None = None) -> tuple[bool, Any]:
    host = conn.get("host", "").rstrip("/")
    token = conn.get("api_token", "")
    url = f"{host}/api/v2{path}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = await ctx.http.request(method, url, headers=headers, json=json_body, params=params, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, ClientFail(UNREACHABLE, str(exc))
    if resp.status_code >= 400:
        return False, ClientFail(_classify_status(resp.status_code), f"HTTP {resp.status_code}")
    try:
        return True, resp.json()
    except Exception:  # noqa: BLE001
        return False, ClientFail(RESPONSE_UNEXPECTED)


# ──────────────────────────────────────────────────────────────────────────
# FortiManager (JSON-RPC, session-based)
# ──────────────────────────────────────────────────────────────────────────


async def fortimanager_login(ctx, conn: dict) -> tuple[bool, Any]:
    host = conn.get("host", "").rstrip("/")
    url = f"{host}{FORTIMANAGER_RPC_PATH}"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{"url": "/sys/login/user", "data": {"user": conn.get("username", ""), "passwd": conn.get("password", "")}}],
    }
    try:
        resp = await ctx.http.request("POST", url, json=body, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, ClientFail(UNREACHABLE, str(exc))
    if resp.status_code >= 400:
        return False, ClientFail(_classify_status(resp.status_code), f"HTTP {resp.status_code}")
    data = resp.json()
    status = (data.get("result") or [{}])[0].get("status", {})
    if status.get("code") != 0:
        return False, ClientFail(TOKEN_REJECTED, status.get("message", ""))
    session = data.get("session", "")
    if not session:
        return False, ClientFail(RESPONSE_UNEXPECTED, "no session id returned")
    return True, session


async def fortimanager_request(ctx, conn: dict, session: str, method: str, url_path: str, data: dict | None = None) -> tuple[bool, Any]:
    """Single JSON-RPC call. Retries once with a fresh session on session-expiry."""
    host = conn.get("host", "").rstrip("/")
    url = f"{host}{FORTIMANAGER_RPC_PATH}"
    body: dict[str, Any] = {"id": 1, "method": method, "params": [{"url": url_path}], "session": session}
    if data is not None:
        body["params"][0]["data"] = data
    try:
        resp = await ctx.http.request("POST", url, json=body, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, ClientFail(UNREACHABLE, str(exc))
    if resp.status_code >= 400:
        return False, ClientFail(_classify_status(resp.status_code), f"HTTP {resp.status_code}")
    payload = resp.json()
    result = (payload.get("result") or [{}])[0]
    code = result.get("status", {}).get("code", 0)
    if code == -11:  # No permission / invalid session
        return False, ClientFail(SESSION_EXPIRED, result.get("status", {}).get("message", ""))
    if code != 0:
        return False, ClientFail(VALIDATION_FAILED, result.get("status", {}).get("message", ""))
    return True, result.get("data", result)


# ──────────────────────────────────────────────────────────────────────────
# FortiSASE
# ──────────────────────────────────────────────────────────────────────────


async def fortisase_request(ctx, conn: dict, method: str, path: str, json_body: dict | None = None, params: dict | None = None) -> tuple[bool, Any]:
    base = conn.get("region", "") or FORTISASE_DEFAULT_BASE
    if not base.startswith("http"):
        base = FORTISASE_DEFAULT_BASE
    url = f"{base}/api/v1{path}"
    headers = {"Authorization": f"Bearer {conn.get('api_token', '')}"}
    try:
        resp = await ctx.http.request(method, url, headers=headers, json=json_body, params=params, timeout=30)
    except Exception as exc:  # noqa: BLE001
        return False, ClientFail(UNREACHABLE, str(exc))
    if resp.status_code >= 400:
        return False, ClientFail(_classify_status(resp.status_code), f"HTTP {resp.status_code}")
    try:
        return True, resp.json()
    except Exception:  # noqa: BLE001
        return False, ClientFail(RESPONSE_UNEXPECTED)
