"""Chat functions for Fortinet Connector: connection management (FortiGate +
FortiManager + FortiSASE, three independent BYOK auth mechanisms). Built on
fortinet_client.py / schemas.py, following the same shape as Cisco Secure
Access Connector's handlers_connection.py.
"""
from __future__ import annotations

import json
import uuid

from imperal_sdk import ActionResult

import fortinet_client as fc
from app import ext, chat
from schemas import (
    NoParams,
    ConnectFortiGateParams, ConnectFortiManagerParams, ConnectFortiSaseParams,
    ProviderConnection, ProviderConnectionList,
    DisconnectParams, DeleteResult,
)

_SECRET_NAME = "fortinet_connections"


async def _load_connections(ctx) -> list[dict]:
    raw = await ctx.secrets.get(_SECRET_NAME)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []


async def _save_connections(ctx, connections: list[dict]) -> None:
    await ctx.secrets.set(_SECRET_NAME, json.dumps(connections))


async def _resolve_connection(ctx, kind: str, connection_id: str = "") -> dict | None:
    connections = [c for c in await _load_connections(ctx) if c.get("kind") == kind]
    if not connections:
        return None
    if connection_id:
        for c in connections:
            if c.get("id") == connection_id:
                return c
        return None
    return connections[0]


async def _authed_fortigate(ctx, connection_id: str = "") -> dict | ActionResult:
    conn = await _resolve_connection(ctx, "fortigate", connection_id)
    if conn is None:
        return ActionResult(success=False, error=fc._MESSAGES[fc.ACCOUNT_MISSING])
    return conn


async def _authed_fortisase(ctx, connection_id: str = "") -> dict | ActionResult:
    conn = await _resolve_connection(ctx, "fortisase", connection_id)
    if conn is None:
        return ActionResult(success=False, error=fc._MESSAGES[fc.ACCOUNT_MISSING])
    return conn


async def _authed_fortimanager(ctx, connection_id: str = "") -> tuple[dict, str] | ActionResult:
    conn = await _resolve_connection(ctx, "fortimanager", connection_id)
    if conn is None:
        return ActionResult(success=False, error=fc._MESSAGES[fc.ACCOUNT_MISSING])
    ok, session = await fc.fortimanager_login(ctx, conn)
    if not ok:
        return ActionResult(success=False, error=session.message())
    return conn, session


def _connection_to_entity(c: dict) -> ProviderConnection:
    kind = c.get("kind", "")
    if kind == "fortigate":
        detail = c.get("host", "")
    elif kind == "fortimanager":
        detail = f"{c.get('host', '')} (ADOM: {c.get('adom', 'root')})"
    else:
        detail = c.get("region", "") or "FortiCloud"
    return ProviderConnection(
        id=c.get("id", ""),
        title=c.get("label") or c.get("host") or kind,
        kind=kind,
        connected=True,
        detail=detail,
    )


@chat.function(
    "connect_fortigate",
    "Connect a FortiGate device by saving its host and REST API Admin token, after checking they actually work. Create a REST API Admin under System > Administrators in the FortiGate itself.",
    action_type="write",
)
async def connect_fortigate(ctx, params: ConnectFortiGateParams) -> ActionResult:
    conn = {"host": params.host.rstrip("/"), "api_token": params.api_token}
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/monitor/system/status")
    if not ok:
        return ActionResult(success=False, error=data.message())
    connections = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()), "kind": "fortigate",
        "host": conn["host"], "api_token": params.api_token,
        "label": params.label or conn["host"],
    }
    connections.append(entry)
    await _save_connections(ctx, connections)
    return ActionResult(success=True, data=_connection_to_entity(entry))


@chat.function(
    "connect_fortimanager",
    "Connect a FortiManager by saving its host, username, password and ADOM, after checking the login actually works. Session-based login re-authenticates transparently on every call.",
    action_type="write",
)
async def connect_fortimanager(ctx, params: ConnectFortiManagerParams) -> ActionResult:
    conn = {"host": params.host.rstrip("/"), "username": params.username, "password": params.password, "adom": params.adom or "root"}
    ok, session = await fc.fortimanager_login(ctx, conn)
    if not ok:
        return ActionResult(success=False, error=session.message())
    connections = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()), "kind": "fortimanager",
        "host": conn["host"], "username": params.username, "password": params.password,
        "adom": conn["adom"], "label": params.label or conn["host"],
    }
    connections.append(entry)
    await _save_connections(ctx, connections)
    return ActionResult(success=True, data=_connection_to_entity(entry))


@chat.function(
    "connect_fortisase",
    "Connect a FortiSASE/FortiCloud tenant by saving its API token, after checking it actually works. Create one in FortiCloud under Identity & Access Management > API tokens.",
    action_type="write",
)
async def connect_fortisase(ctx, params: ConnectFortiSaseParams) -> ActionResult:
    conn = {"api_token": params.api_token, "region": params.region}
    ok, data = await fc.fortisase_request(ctx, conn, "GET", "/endpoints")
    if not ok:
        return ActionResult(success=False, error=data.message())
    connections = await _load_connections(ctx)
    entry = {
        "id": str(uuid.uuid4()), "kind": "fortisase",
        "api_token": params.api_token, "region": params.region,
        "label": params.label or "FortiSASE tenant",
    }
    connections.append(entry)
    await _save_connections(ctx, connections)
    return ActionResult(success=True, data=_connection_to_entity(entry))


@chat.function(
    "disconnect_fortinet",
    "Disconnect and forget a stored FortiGate, FortiManager, or FortiSASE connection.",
    action_type="write",
)
async def disconnect_fortinet(ctx, params: DisconnectParams) -> ActionResult:
    connections = await _load_connections(ctx)
    remaining = [c for c in connections if c.get("id") != params.connection_id]
    if len(remaining) == len(connections):
        return ActionResult(success=False, error="No such connection.")
    await _save_connections(ctx, remaining)
    return ActionResult(success=True, data=DeleteResult(id=params.connection_id, deleted=True))


@chat.function(
    "list_connections",
    "List all connected FortiGate, FortiManager, and FortiSASE connections.",
    action_type="read",
    data_model=ProviderConnectionList,
)
async def list_connections(ctx, params: NoParams) -> ActionResult:
    connections = await _load_connections(ctx)
    items = [_connection_to_entity(c) for c in connections]
    return ActionResult(success=True, data=ProviderConnectionList(title=f"{len(items)} connection(s)", items=items))
