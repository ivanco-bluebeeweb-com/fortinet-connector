"""Chat functions for FortiGate (device-level): firewall policies, address/
service objects, interfaces, system status, VPN tunnels. Built on
fortinet_client.py / schemas.py, following the same shape as Cisco Secure
Access Connector's handlers_umbrella.py.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import fortinet_client as fc
from app import chat
from handlers_connection import _authed_fortigate
from schemas import (
    ListFirewallPoliciesParams, FirewallPolicy, FirewallPolicyList,
    GetFirewallPolicyParams, CreateFirewallPolicyParams,
    UpdateFirewallPolicyParams, DeleteFirewallPolicyParams,
    ReorderFirewallPolicyParams, DeleteResult,
    ListAddressObjectsParams, AddressObject, AddressObjectList,
    CreateAddressObjectParams, UpdateAddressObjectParams, DeleteAddressObjectParams,
    ListAddressGroupsParams, AddressGroup, AddressGroupList,
    ListServiceObjectsParams, ServiceObject, ServiceObjectList,
    CreateServiceObjectParams, UpdateServiceObjectParams, DeleteServiceObjectParams,
    ListInterfacesParams, Interface, InterfaceList,
    GetSystemStatusParams, SystemStatus,
    ListVpnTunnelsParams, VpnTunnel, VpnTunnelList,
)


@chat.function(
    "list_firewall_policies",
    "List firewall policies configured on the connected FortiGate device.",
    action_type="read",
    data_model=FirewallPolicyList,
)
async def list_firewall_policies(ctx, params: ListFirewallPoliciesParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/firewall/policy")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [
        FirewallPolicy(
            id=str(p.get("policyid", "")), title=p.get("name", ""), policyid=p.get("policyid", 0),
            action=p.get("action", ""), srcintf=",".join(i.get("name", "") for i in p.get("srcintf", [])),
            dstintf=",".join(i.get("name", "") for i in p.get("dstintf", [])), status=p.get("status", ""),
        )
        for p in data.get("results", [])
    ]
    return ActionResult(success=True, data=FirewallPolicyList(title=f"{len(items)} polic{'y' if len(items)==1 else 'ies'}", items=items))


@chat.function(
    "get_firewall_policy",
    "Get one FortiGate firewall policy by id.",
    action_type="read",
    data_model=FirewallPolicy,
)
async def get_firewall_policy(ctx, params: GetFirewallPolicyParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", f"/cmdb/firewall/policy/{params.policyid}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    p = (data.get("results") or [{}])[0]
    return ActionResult(success=True, data=FirewallPolicy(
        id=str(p.get("policyid", "")), title=p.get("name", ""), policyid=p.get("policyid", 0),
        action=p.get("action", ""), srcintf=",".join(i.get("name", "") for i in p.get("srcintf", [])),
        dstintf=",".join(i.get("name", "") for i in p.get("dstintf", [])), status=p.get("status", ""),
    ))


@chat.function(
    "create_firewall_policy",
    "Create a new firewall policy on the connected FortiGate device.",
    action_type="write",
)
async def create_firewall_policy(ctx, params: CreateFirewallPolicyParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {
        "name": params.name, "srcintf": [{"name": params.srcintf}], "dstintf": [{"name": params.dstintf}],
        "srcaddr": [{"name": params.srcaddr}], "dstaddr": [{"name": params.dstaddr}],
        "action": params.action, "schedule": params.schedule, "service": [{"name": params.service}],
    }
    ok, data = await fc.fortigate_request(ctx, conn, "POST", "/cmdb/firewall/policy", json_body=body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=FirewallPolicy(id=str(data.get("mkey", "")), title=params.name, action=params.action))


@chat.function(
    "update_firewall_policy",
    "Update a FortiGate firewall policy's action and/or enabled status.",
    action_type="write",
)
async def update_firewall_policy(ctx, params: UpdateFirewallPolicyParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {}
    if params.action:
        body["action"] = params.action
    if params.status:
        body["status"] = params.status
    ok, data = await fc.fortigate_request(ctx, conn, "PUT", f"/cmdb/firewall/policy/{params.policyid}", json_body=body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=FirewallPolicy(id=params.policyid, title="Updated"))


@chat.function(
    "delete_firewall_policy",
    "Permanently delete a FortiGate firewall policy by id.",
    action_type="write",
)
async def delete_firewall_policy(ctx, params: DeleteFirewallPolicyParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "DELETE", f"/cmdb/firewall/policy/{params.policyid}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=DeleteResult(id=params.policyid, deleted=True))


@chat.function(
    "reorder_firewall_policy",
    "Move a FortiGate firewall policy to just before or after another policy in the rule order.",
    action_type="write",
)
async def reorder_firewall_policy(ctx, params: ReorderFirewallPolicyParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    q = {}
    if params.before_policyid:
        q = {"action": "move", "before": params.before_policyid}
    elif params.after_policyid:
        q = {"action": "move", "after": params.after_policyid}
    ok, data = await fc.fortigate_request(ctx, conn, "PUT", f"/cmdb/firewall/policy/{params.policyid}", params=q)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=DeleteResult(id=params.policyid, deleted=False, title="Reordered"))


@chat.function(
    "list_address_objects",
    "List firewall address objects defined on the connected FortiGate device.",
    action_type="read",
    data_model=AddressObjectList,
)
async def list_address_objects(ctx, params: ListAddressObjectsParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/firewall/address")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [AddressObject(id=a.get("name", ""), title=a.get("name", ""), subnet=a.get("subnet", ""), type=a.get("type", "")) for a in data.get("results", [])]
    return ActionResult(success=True, data=AddressObjectList(title=f"{len(items)} address object(s)", items=items))


@chat.function(
    "create_address_object",
    "Create a new firewall address object on the connected FortiGate device.",
    action_type="write",
)
async def create_address_object(ctx, params: CreateAddressObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "POST", "/cmdb/firewall/address", json_body={"name": params.name, "subnet": params.subnet})
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=AddressObject(id=params.name, title=params.name, subnet=params.subnet))


@chat.function(
    "update_address_object",
    "Update a firewall address object's subnet.",
    action_type="write",
)
async def update_address_object(ctx, params: UpdateAddressObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {"subnet": params.subnet} if params.subnet else {}
    ok, data = await fc.fortigate_request(ctx, conn, "PUT", f"/cmdb/firewall/address/{params.name}", json_body=body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=AddressObject(id=params.name, title=params.name))


@chat.function(
    "delete_address_object",
    "Permanently delete a firewall address object by name.",
    action_type="write",
)
async def delete_address_object(ctx, params: DeleteAddressObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "DELETE", f"/cmdb/firewall/address/{params.name}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=DeleteResult(id=params.name, deleted=True))


@chat.function(
    "list_address_groups",
    "List firewall address groups defined on the connected FortiGate device.",
    action_type="read",
    data_model=AddressGroupList,
)
async def list_address_groups(ctx, params: ListAddressGroupsParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/firewall/addrgrp")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [AddressGroup(id=g.get("name", ""), title=g.get("name", ""), member_count=len(g.get("member", []))) for g in data.get("results", [])]
    return ActionResult(success=True, data=AddressGroupList(title=f"{len(items)} address group(s)", items=items))


@chat.function(
    "list_service_objects",
    "List firewall service objects defined on the connected FortiGate device.",
    action_type="read",
    data_model=ServiceObjectList,
)
async def list_service_objects(ctx, params: ListServiceObjectsParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/firewall.service/custom")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [ServiceObject(id=s.get("name", ""), title=s.get("name", ""), protocol=s.get("protocol", ""), port_range=s.get("tcp-portrange", "") or s.get("udp-portrange", "")) for s in data.get("results", [])]
    return ActionResult(success=True, data=ServiceObjectList(title=f"{len(items)} service object(s)", items=items))


@chat.function(
    "create_service_object",
    "Create a new firewall service object on the connected FortiGate device.",
    action_type="write",
)
async def create_service_object(ctx, params: CreateServiceObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {"name": params.name, "protocol": params.protocol, "tcp-portrange": params.port_range}
    ok, data = await fc.fortigate_request(ctx, conn, "POST", "/cmdb/firewall.service/custom", json_body=body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=ServiceObject(id=params.name, title=params.name, port_range=params.port_range))


@chat.function(
    "update_service_object",
    "Update a firewall service object's port range.",
    action_type="write",
)
async def update_service_object(ctx, params: UpdateServiceObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    body = {"tcp-portrange": params.port_range} if params.port_range else {}
    ok, data = await fc.fortigate_request(ctx, conn, "PUT", f"/cmdb/firewall.service/custom/{params.name}", json_body=body)
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=ServiceObject(id=params.name, title=params.name))


@chat.function(
    "delete_service_object",
    "Permanently delete a firewall service object by name.",
    action_type="write",
)
async def delete_service_object(ctx, params: DeleteServiceObjectParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "DELETE", f"/cmdb/firewall.service/custom/{params.name}")
    if not ok:
        return ActionResult(success=False, error=data.message())
    return ActionResult(success=True, data=DeleteResult(id=params.name, deleted=True))


@chat.function(
    "list_interfaces",
    "List network interfaces on the connected FortiGate device.",
    action_type="read",
    data_model=InterfaceList,
)
async def list_interfaces(ctx, params: ListInterfacesParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/system/interface")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [Interface(id=i.get("name", ""), title=i.get("name", ""), ip=i.get("ip", ""), status=i.get("status", ""), role=i.get("role", "")) for i in data.get("results", [])]
    return ActionResult(success=True, data=InterfaceList(title=f"{len(items)} interface(s)", items=items))


@chat.function(
    "get_system_status",
    "Get FortiGate system status: firmware version, serial number, hostname, uptime.",
    action_type="read",
    data_model=SystemStatus,
)
async def get_system_status(ctx, params: GetSystemStatusParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/monitor/system/status")
    if not ok:
        return ActionResult(success=False, error=data.message())
    r = data.get("results", data)
    return ActionResult(success=True, data=SystemStatus(
        id="system_status", title=r.get("hostname", "FortiGate"), version=r.get("version", ""),
        serial=r.get("serial", ""), hostname=r.get("hostname", ""), uptime_seconds=r.get("uptime", 0),
    ))


@chat.function(
    "list_vpn_tunnels",
    "List IPsec and SSL VPN tunnels configured on the connected FortiGate device.",
    action_type="read",
    data_model=VpnTunnelList,
)
async def list_vpn_tunnels(ctx, params: ListVpnTunnelsParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    ok, data = await fc.fortigate_request(ctx, conn, "GET", "/monitor/vpn/ipsec")
    if not ok:
        return ActionResult(success=False, error=data.message())
    items = [VpnTunnel(id=t.get("name", ""), title=t.get("name", ""), type="ipsec", status=t.get("status", "")) for t in data.get("results", [])]
    return ActionResult(success=True, data=VpnTunnelList(title=f"{len(items)} VPN tunnel(s)", items=items))
