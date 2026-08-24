"""Chat functions for FortiManager (fleet management): ADOMs, managed
devices, policy packages, per-package firewall policies, global address
objects. Built on fortinet_client.py / schemas.py, JSON-RPC session model.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import fortinet_client as fc
from app import chat
from handlers_connection import _authed_fortimanager
from schemas import (
    ListAdomsParams, Adom, AdomList,
    ListManagedDevicesParams, ManagedDevice, ManagedDeviceList,
    GetManagedDeviceParams,
    ListPolicyPackagesParams, PolicyPackage, PolicyPackageList,
    ListFmgFirewallPoliciesParams, FmgFirewallPolicy, FmgFirewallPolicyList,
    ListFmgAddressObjectsParams, FmgAddressObject, FmgAddressObjectList,
    CreateFmgAddressObjectParams, UpdateFmgAddressObjectParams, DeleteFmgAddressObjectParams,
    DeleteResult,
)


@chat.function(
    "list_adoms",
    "List Administrative Domains (ADOMs) visible on the connected FortiManager.",
    action_type="read",
    data_model=AdomList,
)
async def list_adoms(ctx, params: ListAdomsParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", "/dvmdb/adom")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [Adom(id=a.get("name", ""), title=a.get("name", ""), os_ver=str(a.get("os_ver", ""))) for a in data]
    return ActionResult(success=True, data=AdomList(title=f"{len(items)} ADOM(s)", items=items))


@chat.function(
    "list_managed_devices",
    "List FortiGate devices managed by the connected FortiManager, in the configured ADOM.",
    action_type="read",
    data_model=ManagedDeviceList,
)
async def list_managed_devices(ctx, params: ListManagedDevicesParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    adom = conn.get("adom", "root")
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", f"/dvmdb/adom/{adom}/device")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [
        ManagedDevice(
            id=d.get("name", ""), title=d.get("name", ""), ip=d.get("ip", ""),
            platform=d.get("platform_str", ""), status="online" if d.get("conn_status") == 1 else "offline",
            os_ver=str(d.get("os_ver", "")),
        )
        for d in data
    ]
    return ActionResult(success=True, data=ManagedDeviceList(title=f"{len(items)} managed device(s)", items=items))


@chat.function(
    "get_managed_device",
    "Get one FortiManager-managed device by name.",
    action_type="read",
    data_model=ManagedDevice,
)
async def get_managed_device(ctx, params: GetManagedDeviceParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    adom = conn.get("adom", "root")
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", f"/dvmdb/adom/{adom}/device/{params.device_name}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    d = data[0] if isinstance(data, list) else data
    return ActionResult(success=True, data=ManagedDevice(
        id=d.get("name", ""), title=d.get("name", ""), ip=d.get("ip", ""),
        platform=d.get("platform_str", ""), status="online" if d.get("conn_status") == 1 else "offline",
        os_ver=str(d.get("os_ver", "")),
    ))


@chat.function(
    "list_policy_packages",
    "List policy packages defined on the connected FortiManager, in the configured ADOM.",
    action_type="read",
    data_model=PolicyPackageList,
)
async def list_policy_packages(ctx, params: ListPolicyPackagesParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    adom = conn.get("adom", "root")
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", f"/pm/pkg/adom/{adom}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [PolicyPackage(id=p.get("name", ""), title=p.get("name", ""), scope_member_count=len(p.get("scope member", []))) for p in data]
    return ActionResult(success=True, data=PolicyPackageList(title=f"{len(items)} policy package(s)", items=items))


@chat.function(
    "list_fmg_firewall_policies",
    "List firewall policies inside one FortiManager policy package.",
    action_type="read",
    data_model=FmgFirewallPolicyList,
)
async def list_fmg_firewall_policies(ctx, params: ListFmgFirewallPoliciesParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    adom = conn.get("adom", "root")
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", f"/pm/config/adom/{adom}/pkg/{params.package}/firewall/policy")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [FmgFirewallPolicy(id=str(p.get("policyid", "")), title=p.get("name", ""), policyid=p.get("policyid", 0), action=p.get("action", ""), status=p.get("status", "")) for p in data]
    return ActionResult(success=True, data=FmgFirewallPolicyList(title=f"{len(items)} polic{'y' if len(items)==1 else 'ies'}", items=items))


@chat.function(
    "list_fmg_address_objects",
    "List global (shared) address objects defined on the connected FortiManager.",
    action_type="read",
    data_model=FmgAddressObjectList,
)
async def list_fmg_address_objects(ctx, params: ListFmgAddressObjectsParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    ok, data = await fc.fortimanager_request(ctx, conn, session, "get", "/pm/config/global/obj/firewall/address")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [FmgAddressObject(id=a.get("name", ""), title=a.get("name", ""), subnet=" ".join(str(x) for x in a.get("subnet", []))) for a in data]
    return ActionResult(success=True, data=FmgAddressObjectList(title=f"{len(items)} address object(s)", items=items))


@chat.function(
    "create_fmg_address_object",
    "Create a global (shared) address object on the connected FortiManager.",
    action_type="write",
)
async def create_fmg_address_object(ctx, params: CreateFmgAddressObjectParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    body = {"name": params.name, "subnet": params.subnet.split()}
    ok, data = await fc.fortimanager_request(ctx, conn, session, "add", "/pm/config/global/obj/firewall/address", body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=FmgAddressObject(id=params.name, title=params.name, subnet=params.subnet))


@chat.function(
    "update_fmg_address_object",
    "Update a global (shared) address object on the connected FortiManager.",
    action_type="write",
)
async def update_fmg_address_object(ctx, params: UpdateFmgAddressObjectParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    body: dict = {}
    if params.subnet:
        body["subnet"] = params.subnet.split()
    ok, data = await fc.fortimanager_request(ctx, conn, session, "set", f"/pm/config/global/obj/firewall/address/{params.name}", body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=FmgAddressObject(id=params.name, title=params.name, subnet=params.subnet))


@chat.function(
    "delete_fmg_address_object",
    "Permanently delete a global (shared) address object from the connected FortiManager.",
    action_type="write",
)
async def delete_fmg_address_object(ctx, params: DeleteFmgAddressObjectParams) -> ActionResult:
    auth = await _authed_fortimanager(ctx, params.connection_id)
    if isinstance(auth, ActionResult):
        return auth
    conn, session = auth
    ok, data = await fc.fortimanager_request(ctx, conn, session, "delete", f"/pm/config/global/obj/firewall/address/{params.name}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=DeleteResult(id=params.name, deleted=True))
