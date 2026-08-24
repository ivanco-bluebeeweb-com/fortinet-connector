"""Fortinet Connector -- center panels: base overview + FortiGate/
FortiManager/FortiSASE overlay panels, per UI_COMPONENT_PLAN.md §1.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
import handlers_connection as h
import handlers_fortigate as fg
import handlers_fortimanager as fm
import handlers_fortisase as fs
from schemas import (
    ListFirewallPoliciesParams, ListAddressObjectsParams, ListInterfacesParams,
    ListAdomsParams, ListManagedDevicesParams, ListPolicyPackagesParams,
    ListEndpointsParams, ListSasePoliciesParams, ListSdwanSitesParams,
)


def _status_badge(status: str) -> ui.UINode:
    s = (status or "").lower()
    color = "success" if s in ("enable", "online", "up", "connected") else ("error" if s in ("disable", "offline", "down") else "default")
    return ui.Badge(label=status or "unknown", color=color)


@ext.panel("fortinet_center", slot="center")
async def fortinet_center(ctx, **kwargs) -> ui.UINode:
    """Base (non-overlay) center panel -- rendered before any sidebar item is
    clicked, per UI_INTERFACE_STANDARD.md's mandatory base-center-panel rule."""
    result = await h.list_connections(ctx, h.NoParams())
    items = result.data.items if result.success and result.data else []
    if not items:
        return ui.Empty(message="Connect FortiGate, FortiManager, or FortiSASE first.", icon="Shield")
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("Fortinet", variant="heading"),
        ui.Text(
            "Ask Webbee to list firewall policies, address/service objects, interfaces, VPN tunnels, ADOMs, managed devices, policy packages, SASE endpoints/policies, SD-WAN sites, security events, or run an estate health audit.",
            variant="caption",
        ),
    ])


@ext.panel("fortinet_fortigate_overview", slot="center", title="FortiGate", center_overlay=True)
async def fortinet_fortigate_overview(ctx, **kwargs) -> ui.UINode:
    pol_res = await fg.list_firewall_policies(ctx, ListFirewallPoliciesParams())
    if not pol_res.success:
        return ui.Alert(type="error", message=pol_res.error or "Could not reach FortiGate.")
    addr_res = await fg.list_address_objects(ctx, ListAddressObjectsParams())
    iface_res = await fg.list_interfaces(ctx, ListInterfacesParams())
    policies = pol_res.data.items if pol_res.data else []
    addr_count = len(addr_res.data.items) if addr_res.success and addr_res.data else 0
    iface_count = len(iface_res.data.items) if iface_res.success and iface_res.data else 0
    rows = [{
        "name": p.title, "action": p.action, "src": p.srcintf, "dst": p.dstintf,
        "status": p.status,
    } for p in policies]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("FortiGate", variant="heading"),
        ui.Stats(children=[
            ui.Stat(label="Firewall policies", value=str(len(policies))),
            ui.Stat(label="Address objects", value=str(addr_count)),
            ui.Stat(label="Interfaces", value=str(iface_count)),
        ]),
        ui.Divider(),
        ui.Text("Firewall policies", variant="subtitle"),
        ui.DataTable(columns=[
            {"key": "name", "label": "Name"}, {"key": "action", "label": "Action"},
            {"key": "src", "label": "Source"}, {"key": "dst", "label": "Destination"},
            {"key": "status", "label": "Status"},
        ], rows=rows) if rows else ui.Empty(message="No firewall policies found", icon="Shield"),
    ])


@ext.panel("fortinet_fortimanager_overview", slot="center", title="FortiManager", center_overlay=True)
async def fortinet_fortimanager_overview(ctx, **kwargs) -> ui.UINode:
    dev_res = await fm.list_managed_devices(ctx, ListManagedDevicesParams())
    if not dev_res.success:
        return ui.Alert(type="error", message=dev_res.error or "Could not reach FortiManager.")
    adom_res = await fm.list_adoms(ctx, ListAdomsParams())
    pkg_res = await fm.list_policy_packages(ctx, ListPolicyPackagesParams())
    devices = dev_res.data.items if dev_res.data else []
    adom_count = len(adom_res.data.items) if adom_res.success and adom_res.data else 0
    pkg_count = len(pkg_res.data.items) if pkg_res.success and pkg_res.data else 0
    rows = [{
        "name": d.title, "ip": d.ip, "platform": d.platform,
        "status": d.status, "os_ver": d.os_ver,
    } for d in devices]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("FortiManager", variant="heading"),
        ui.Stats(children=[
            ui.Stat(label="ADOMs", value=str(adom_count)),
            ui.Stat(label="Managed devices", value=str(len(devices))),
            ui.Stat(label="Policy packages", value=str(pkg_count)),
        ]),
        ui.Divider(),
        ui.Text("Managed devices", variant="subtitle"),
        ui.DataTable(columns=[
            {"key": "name", "label": "Name"}, {"key": "ip", "label": "IP"},
            {"key": "platform", "label": "Platform"}, {"key": "status", "label": "Status"},
            {"key": "os_ver", "label": "OS version"},
        ], rows=rows) if rows else ui.Empty(message="No managed devices found", icon="Server"),
    ])


@ext.panel("fortinet_fortisase_overview", slot="center", title="FortiSASE", center_overlay=True)
async def fortinet_fortisase_overview(ctx, **kwargs) -> ui.UINode:
    ep_res = await fs.list_endpoints(ctx, ListEndpointsParams())
    if not ep_res.success:
        return ui.Alert(type="error", message=ep_res.error or "Could not reach FortiSASE.")
    pol_res = await fs.list_sase_policies(ctx, ListSasePoliciesParams())
    site_res = await fs.list_sdwan_sites(ctx, ListSdwanSitesParams())
    endpoints = ep_res.data.items if ep_res.data else []
    pol_count = len(pol_res.data.items) if pol_res.success and pol_res.data else 0
    site_count = len(site_res.data.items) if site_res.success and site_res.data else 0
    rows = [{
        "user": e.user, "os": e.os, "status": e.status,
    } for e in endpoints]
    return ui.Stack(direction="v", gap=3, align="stretch", children=[
        ui.Text("FortiSASE", variant="heading"),
        ui.Stats(children=[
            ui.Stat(label="Endpoints", value=str(len(endpoints))),
            ui.Stat(label="SASE policies", value=str(pol_count)),
            ui.Stat(label="SD-WAN sites", value=str(site_count)),
        ]),
        ui.Divider(),
        ui.Text("Endpoints", variant="subtitle"),
        ui.DataTable(columns=[
            {"key": "user", "label": "User"}, {"key": "os", "label": "OS"},
            {"key": "status", "label": "Status"},
        ], rows=rows) if rows else ui.Empty(message="No endpoints found", icon="Laptop"),
    ])
