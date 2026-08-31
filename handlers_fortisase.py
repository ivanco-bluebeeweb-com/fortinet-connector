"""Chat functions for FortiSASE (cloud ZTNA/SD-WAN): endpoints, SASE
policies, SD-WAN sites, security events. Built on fortinet_client.py /
schemas.py, following the same shape as Cisco Secure Access Connector's
handlers_meraki.py.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import fortinet_client as fc
from app import chat
from handlers_connection import _authed_fortisase
from schemas import (
    ListEndpointsParams, Endpoint, EndpointList,
    ListSasePoliciesParams, SasePolicy, SasePolicyList,
    CreateSasePolicyParams, UpdateSasePolicyParams, DeleteSasePolicyParams,
    DeleteResult,
    ListSdwanSitesParams, SdwanSite, SdwanSiteList,
    ListSecurityEventsParams, SecurityEvent, SecurityEventList,
)


@chat.function(
    "list_endpoints",
    "List endpoints (managed devices/users) enrolled in the connected FortiSASE tenant.",
    action_type="read",
    data_model=EndpointList,
)
async def list_endpoints(ctx, params: ListEndpointsParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "GET", "/endpoints")
    if not ok:
        return ActionResult.error(data.message())
    items = [Endpoint(id=str(e.get("id", "")), title=e.get("hostname", ""), user=e.get("user", ""), os=e.get("os", ""), status=e.get("status", "")) for e in data.get("results", data if isinstance(data, list) else [])]
    return ActionResult.success(EndpointList(title=f"{len(items)} endpoint(s)", items=items), summary="Endpoints listed.")


@chat.function(
    "list_sase_policies",
    "List SASE access policies configured on the connected FortiSASE tenant.",
    action_type="read",
    data_model=SasePolicyList,
)
async def list_sase_policies(ctx, params: ListSasePoliciesParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "GET", "/policies")
    if not ok:
        return ActionResult.error(data.message())
    items = [SasePolicy(id=str(p.get("id", "")), title=p.get("name", ""), action=p.get("action", ""), status=p.get("status", "")) for p in data.get("results", data if isinstance(data, list) else [])]
    return ActionResult.success(SasePolicyList(title=f"{len(items)} SASE polic{'y' if len(items)==1 else 'ies'}", items=items), summary="Sase policies listed.")


@chat.function(
    "create_sase_policy",
    "Create a new SASE access policy on the connected FortiSASE tenant.",
    action_type="write",
)
async def create_sase_policy(ctx, params: CreateSasePolicyParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "POST", "/policies", json_body={"name": params.name, "action": params.action})
    if not ok:
        return ActionResult.error(data.message())
    return ActionResult.success(SasePolicy(id=str(data.get("id", "")), title=params.name, action=params.action, status="enable"), summary="Sase policy created.")


@chat.function(
    "update_sase_policy",
    "Update an existing SASE access policy on the connected FortiSASE tenant.",
    action_type="write",
)
async def update_sase_policy(ctx, params: UpdateSasePolicyParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {}
    if params.action:
        body["action"] = params.action
    if params.status:
        body["status"] = params.status
    ok, data = await fc.fortisase_request(ctx, conn, "PUT", f"/policies/{params.policy_id}", json_body=body)
    if not ok:
        return ActionResult.error(data.message())
    return ActionResult.success(SasePolicy(id=params.policy_id, title=data.get("name", ""), action=params.action, status=params.status), summary="Sase policy updated.")


@chat.function(
    "delete_sase_policy",
    "Permanently delete a SASE access policy from the connected FortiSASE tenant.",
    action_type="write",
)
async def delete_sase_policy(ctx, params: DeleteSasePolicyParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "DELETE", f"/policies/{params.policy_id}")
    if not ok:
        return ActionResult.error(data.message())
    return ActionResult.success(DeleteResult(id=params.policy_id, deleted=True), summary="Sase policy deleted.")


@chat.function(
    "list_sdwan_sites",
    "List SD-WAN sites configured on the connected FortiSASE tenant.",
    action_type="read",
    data_model=SdwanSiteList,
)
async def list_sdwan_sites(ctx, params: ListSdwanSitesParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "GET", "/sdwan/sites")
    if not ok:
        return ActionResult.error(data.message())
    items = [SdwanSite(id=str(s.get("id", "")), title=s.get("name", ""), status=s.get("status", "")) for s in data.get("results", data if isinstance(data, list) else [])]
    return ActionResult.success(SdwanSiteList(title=f"{len(items)} SD-WAN site(s)", items=items), summary="Sdwan sites listed.")


@chat.function(
    "list_security_events",
    "List recent security events (threats, blocks, anomalies) from the connected FortiSASE tenant.",
    action_type="read",
    data_model=SecurityEventList,
)
async def list_security_events(ctx, params: ListSecurityEventsParams) -> ActionResult:
    conn = await _authed_fortisase(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortisase_request(ctx, conn, "GET", "/events", params={"limit": params.limit})
    if not ok:
        return ActionResult.error(data.message())
    items = [
        SecurityEvent(id=str(e.get("id", "")), title=e.get("name", e.get("type", "")), severity=e.get("severity", ""), detail=e.get("detail", ""), timestamp=e.get("timestamp", ""))
        for e in data.get("results", data if isinstance(data, list) else [])
    ]
    return ActionResult.success(SecurityEventList(title=f"{len(items)} event(s)", items=items), summary="Security events listed.")
