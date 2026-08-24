"""Pydantic params models + SDL entity contracts for Fortinet Connector.

All params models are module-scope (V17 federal invariant, same rule as
Cisco Secure Access Connector's / Zscaler Connector's schemas.py).
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from imperal_sdk import sdl


class NoParams(BaseModel):
    """Explicit empty params model -- V17 disallows untyped handlers."""
    pass


# ──────────────────────────────────────────────────────────────────────────
# Connection
# ──────────────────────────────────────────────────────────────────────────


class ConnectFortiGateParams(BaseModel):
    host: str = Field(..., description="FortiGate base URL, e.g. 'https://fw01.company.com:443'.")
    api_token: str = Field(..., description="FortiGate REST API Admin token (System > Administrators > REST API Admin).")
    label: str = Field("", description="Optional friendly name for this FortiGate connection.")


class ConnectFortiManagerParams(BaseModel):
    host: str = Field(..., description="FortiManager base URL, e.g. 'https://fmg.company.com'.")
    username: str = Field(..., description="FortiManager administrator username.")
    password: str = Field(..., description="FortiManager administrator password.")
    adom: str = Field("root", description="Administrative Domain to operate in. Defaults to 'root'.")
    label: str = Field("", description="Optional friendly name for this FortiManager connection.")


class ConnectFortiSaseParams(BaseModel):
    api_token: str = Field(..., description="FortiSASE/FortiCloud IAM API token.")
    region: str = Field("", description="Optional FortiSASE region/base URL hint.")
    label: str = Field("", description="Optional friendly name for this FortiSASE connection.")


class ProviderConnection(sdl.Entity):
    id: str = ""
    title: str = ""
    kind: str = ""  # "fortigate" | "fortimanager" | "fortisase"
    connected: bool = False
    detail: str = ""


class ProviderConnectionList(sdl.Entity):
    id: str = "provider_connection_list"
    title: str = ""
    items: list[ProviderConnection] = Field(default_factory=list)


class DisconnectParams(BaseModel):
    connection_id: str = Field(..., description="Connection id to disconnect, from list_connections.")


class DeleteResult(sdl.Entity):
    id: str = ""
    title: str = ""
    deleted: bool = False


# Common connection-id scoping mixins -- one per surface, since a tenant may
# have several FortiGates/FortiManagers/FortiSASE tenants connected at once.
class _FortiGateScoped(BaseModel):
    connection_id: str = Field("", description="Which connected FortiGate device to use. Omit if only one is connected.")


class _FortiManagerScoped(BaseModel):
    connection_id: str = Field("", description="Which connected FortiManager to use. Omit if only one is connected.")


class _FortiSaseScoped(BaseModel):
    connection_id: str = Field("", description="Which connected FortiSASE tenant to use. Omit if only one is connected.")


# ──────────────────────────────────────────────────────────────────────────
# FortiGate -- Firewall Policies
# ──────────────────────────────────────────────────────────────────────────


class ListFirewallPoliciesParams(_FortiGateScoped):
    pass


class FirewallPolicy(sdl.Entity):
    id: str = ""
    title: str = ""
    policyid: int = 0
    action: str = ""  # "accept" | "deny"
    srcintf: str = ""
    dstintf: str = ""
    status: str = ""  # "enable" | "disable"


class FirewallPolicyList(sdl.Entity):
    id: str = "firewall_policy_list"
    title: str = ""
    items: list[FirewallPolicy] = Field(default_factory=list)


class GetFirewallPolicyParams(_FortiGateScoped):
    policyid: str = Field(..., description="Firewall policy id, from list_firewall_policies.")


class CreateFirewallPolicyParams(_FortiGateScoped):
    name: str = Field(..., description="Policy name.")
    srcintf: str = Field(..., description="Source interface name.")
    dstintf: str = Field(..., description="Destination interface name.")
    srcaddr: str = Field("all", description="Source address object name.")
    dstaddr: str = Field("all", description="Destination address object name.")
    action: str = Field("accept", description="accept or deny.")
    schedule: str = Field("always", description="Schedule object name.")
    service: str = Field("ALL", description="Service object name.")


class UpdateFirewallPolicyParams(_FortiGateScoped):
    policyid: str = Field(..., description="Firewall policy id to update.")
    action: str = Field("", description="New action (accept/deny), if changing.")
    status: str = Field("", description="New status (enable/disable), if changing.")


class DeleteFirewallPolicyParams(_FortiGateScoped):
    policyid: str = Field(..., description="Firewall policy id to permanently delete.")


class ReorderFirewallPolicyParams(_FortiGateScoped):
    policyid: str = Field(..., description="Firewall policy id to move.")
    before_policyid: str = Field("", description="Move this policy to just before this policy id.")
    after_policyid: str = Field("", description="Move this policy to just after this policy id.")


# ──────────────────────────────────────────────────────────────────────────
# FortiGate -- Address & Service Objects
# ──────────────────────────────────────────────────────────────────────────


class ListAddressObjectsParams(_FortiGateScoped):
    pass


class AddressObject(sdl.Entity):
    id: str = ""
    title: str = ""
    subnet: str = ""
    type: str = ""


class AddressObjectList(sdl.Entity):
    id: str = "address_object_list"
    title: str = ""
    items: list[AddressObject] = Field(default_factory=list)


class CreateAddressObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Address object name.")
    subnet: str = Field(..., description="Subnet/IP, e.g. '10.0.0.0 255.255.255.0'.")


class UpdateAddressObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Address object name to update.")
    subnet: str = Field("", description="New subnet/IP, if changing.")


class DeleteAddressObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Address object name to permanently delete.")


class ListAddressGroupsParams(_FortiGateScoped):
    pass


class AddressGroup(sdl.Entity):
    id: str = ""
    title: str = ""
    member_count: int = 0


class AddressGroupList(sdl.Entity):
    id: str = "address_group_list"
    title: str = ""
    items: list[AddressGroup] = Field(default_factory=list)


class ListServiceObjectsParams(_FortiGateScoped):
    pass


class ServiceObject(sdl.Entity):
    id: str = ""
    title: str = ""
    protocol: str = ""
    port_range: str = ""


class ServiceObjectList(sdl.Entity):
    id: str = "service_object_list"
    title: str = ""
    items: list[ServiceObject] = Field(default_factory=list)


class CreateServiceObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Service object name.")
    protocol: str = Field("TCP/UDP/SCTP", description="Protocol type.")
    port_range: str = Field(..., description="Destination port range, e.g. '8080-8090'.")


class UpdateServiceObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Service object name to update.")
    port_range: str = Field("", description="New port range, if changing.")


class DeleteServiceObjectParams(_FortiGateScoped):
    name: str = Field(..., description="Service object name to permanently delete.")


# ──────────────────────────────────────────────────────────────────────────
# FortiGate -- Interfaces, System Status, VPN
# ──────────────────────────────────────────────────────────────────────────


class ListInterfacesParams(_FortiGateScoped):
    pass


class Interface(sdl.Entity):
    id: str = ""
    title: str = ""
    ip: str = ""
    status: str = ""
    role: str = ""


class InterfaceList(sdl.Entity):
    id: str = "interface_list"
    title: str = ""
    items: list[Interface] = Field(default_factory=list)


class GetSystemStatusParams(_FortiGateScoped):
    pass


class SystemStatus(sdl.Entity):
    id: str = ""
    title: str = ""
    version: str = ""
    serial: str = ""
    hostname: str = ""
    uptime_seconds: int = 0


class ListVpnTunnelsParams(_FortiGateScoped):
    pass


class VpnTunnel(sdl.Entity):
    id: str = ""
    title: str = ""
    type: str = ""  # "ipsec" | "ssl"
    status: str = ""


class VpnTunnelList(sdl.Entity):
    id: str = "vpn_tunnel_list"
    title: str = ""
    items: list[VpnTunnel] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────
# FortiManager -- ADOMs, Managed Devices, Policy Packages, Global Objects
# ──────────────────────────────────────────────────────────────────────────


class ListAdomsParams(_FortiManagerScoped):
    pass


class Adom(sdl.Entity):
    id: str = ""
    title: str = ""
    os_ver: str = ""


class AdomList(sdl.Entity):
    id: str = "adom_list"
    title: str = ""
    items: list[Adom] = Field(default_factory=list)


class ListManagedDevicesParams(_FortiManagerScoped):
    pass


class ManagedDevice(sdl.Entity):
    id: str = ""
    title: str = ""
    ip: str = ""
    platform: str = ""
    status: str = ""  # "online" | "offline"
    os_ver: str = ""


class ManagedDeviceList(sdl.Entity):
    id: str = "managed_device_list"
    title: str = ""
    items: list[ManagedDevice] = Field(default_factory=list)


class GetManagedDeviceParams(_FortiManagerScoped):
    device_name: str = Field(..., description="Managed device name, from list_managed_devices.")


class ListPolicyPackagesParams(_FortiManagerScoped):
    pass


class PolicyPackage(sdl.Entity):
    id: str = ""
    title: str = ""
    scope_member_count: int = 0


class PolicyPackageList(sdl.Entity):
    id: str = "policy_package_list"
    title: str = ""
    items: list[PolicyPackage] = Field(default_factory=list)


class ListFmgFirewallPoliciesParams(_FortiManagerScoped):
    package: str = Field(..., description="Policy package name, from list_policy_packages.")


class FmgFirewallPolicy(sdl.Entity):
    id: str = ""
    title: str = ""
    policyid: int = 0
    action: str = ""
    status: str = ""


class FmgFirewallPolicyList(sdl.Entity):
    id: str = "fmg_firewall_policy_list"
    title: str = ""
    items: list[FmgFirewallPolicy] = Field(default_factory=list)


class CreateFmgFirewallPolicyParams(_FortiManagerScoped):
    package: str = Field(..., description="Policy package name to add the policy into.")
    name: str = Field(..., description="Policy name.")
    srcintf: str = Field(..., description="Source interface name.")
    dstintf: str = Field(..., description="Destination interface name.")
    action: str = Field("accept", description="accept or deny.")


class UpdateFmgFirewallPolicyParams(_FortiManagerScoped):
    package: str = Field(..., description="Policy package the policy belongs to.")
    policyid: str = Field(..., description="Policy id to update.")
    action: str = Field("", description="New action (accept/deny), if changing.")
    status: str = Field("", description="New status (enable/disable), if changing.")


class DeleteFmgFirewallPolicyParams(_FortiManagerScoped):
    package: str = Field(..., description="Policy package the policy belongs to.")
    policyid: str = Field(..., description="Policy id to permanently delete.")


class InstallPolicyPackageParams(_FortiManagerScoped):
    package: str = Field(..., description="Policy package name to install/deploy.")
    device_names: list[str] = Field(default_factory=list, description="Target managed device names. Empty = every device the package is scoped to.")


class InstallResult(sdl.Entity):
    id: str = ""
    title: str = ""
    task_id: str = ""
    status: str = ""


class ListFmgAddressObjectsParams(_FortiManagerScoped):
    pass


class FmgAddressObject(sdl.Entity):
    id: str = ""
    title: str = ""
    subnet: str = ""


class FmgAddressObjectList(sdl.Entity):
    id: str = "fmg_address_object_list"
    title: str = ""
    items: list[FmgAddressObject] = Field(default_factory=list)


class CreateFmgAddressObjectParams(_FortiManagerScoped):
    name: str = Field(..., description="Global address object name.")
    subnet: str = Field(..., description="Subnet, e.g. '10.0.0.0/24'.")


class UpdateFmgAddressObjectParams(_FortiManagerScoped):
    name: str = Field(..., description="Global address object name to update.")
    subnet: str = Field("", description="New subnet, if changing.")


class DeleteFmgAddressObjectParams(_FortiManagerScoped):
    name: str = Field(..., description="Global address object name to permanently delete.")


# ──────────────────────────────────────────────────────────────────────────
# FortiSASE -- Endpoints, Policies, SD-WAN Sites, Security Events
# ──────────────────────────────────────────────────────────────────────────


class ListEndpointsParams(_FortiSaseScoped):
    pass


class Endpoint(sdl.Entity):
    id: str = ""
    title: str = ""
    user: str = ""
    os: str = ""
    status: str = ""  # "online" | "offline"


class EndpointList(sdl.Entity):
    id: str = "endpoint_list"
    title: str = ""
    items: list[Endpoint] = Field(default_factory=list)


class ListSasePoliciesParams(_FortiSaseScoped):
    pass


class SasePolicy(sdl.Entity):
    id: str = ""
    title: str = ""
    action: str = ""
    status: str = ""


class SasePolicyList(sdl.Entity):
    id: str = "sase_policy_list"
    title: str = ""
    items: list[SasePolicy] = Field(default_factory=list)


class CreateSasePolicyParams(_FortiSaseScoped):
    name: str = Field(..., description="SASE policy name.")
    action: str = Field("allow", description="allow or deny.")


class UpdateSasePolicyParams(_FortiSaseScoped):
    policy_id: str = Field(..., description="SASE policy id to update.")
    action: str = Field("", description="New action, if changing.")
    status: str = Field("", description="New status (enable/disable), if changing.")


class DeleteSasePolicyParams(_FortiSaseScoped):
    policy_id: str = Field(..., description="SASE policy id to permanently delete.")


class ListSdwanSitesParams(_FortiSaseScoped):
    pass


class SdwanSite(sdl.Entity):
    id: str = ""
    title: str = ""
    status: str = ""


class SdwanSiteList(sdl.Entity):
    id: str = "sdwan_site_list"
    title: str = ""
    items: list[SdwanSite] = Field(default_factory=list)


class ListSecurityEventsParams(_FortiSaseScoped):
    limit: int = Field(50, description="Max events to return (1-200).")


class SecurityEvent(sdl.Entity):
    id: str = ""
    title: str = ""
    severity: str = ""
    detail: str = ""
    timestamp: str = ""


class SecurityEventList(sdl.Entity):
    id: str = "security_event_list"
    title: str = ""
    items: list[SecurityEvent] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────
# Bulk + Audit (Tier 3 value-add)
# ──────────────────────────────────────────────────────────────────────────


class BulkFirewallPolicyActionParams(_FortiGateScoped):
    policyids: list[str] = Field(..., description="FortiGate firewall policy ids to act on.")
    new_status: str = Field(..., description="enable or disable.")


class BulkActionOutcome(sdl.Entity):
    id: str = ""
    ok: bool = False
    error: str = ""


class BulkActionResult(sdl.Entity):
    id: str = "bulk_action_result"
    title: str = ""
    items: list[BulkActionOutcome] = Field(default_factory=list)


class AuditFortinetEstateParams(BaseModel):
    pass


class AuditFinding(sdl.Entity):
    id: str = ""
    severity: str = ""  # "info" | "warning" | "critical"
    message: str = ""


class AuditReport(sdl.Entity):
    id: str = "audit_report"
    title: str = ""
    findings: list[AuditFinding] = Field(default_factory=list)
