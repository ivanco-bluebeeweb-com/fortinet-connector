"""Chat functions for Fortinet Connector -- bulk operations and a combined
estate health audit (Tier 3 value-add), same shape as Cisco Secure Access
Connector's handlers_bulk_audit.py.
"""
from __future__ import annotations

from imperal_sdk import ActionResult

import fortinet_client as fc
from app import chat
from handlers_connection import _authed_fortigate, _load_connections
from schemas import (
    BulkFirewallPolicyActionParams, BulkActionOutcome, BulkActionResult,
    AuditFortinetEstateParams, AuditFinding, AuditReport,
)


@chat.function(
    "bulk_firewall_policy_action",
    "Enable or disable several FortiGate firewall policies in one call, by explicit policy ids. Continues past per-item failures and reports each outcome, same convention as every other bulk_* tool in the portfolio.",
    action_type="write",
)
async def bulk_firewall_policy_action(ctx, params: BulkFirewallPolicyActionParams) -> ActionResult:
    conn = await _authed_fortigate(ctx, params.connection_id)
    if isinstance(conn, ActionResult):
        return conn
    items: list[BulkActionOutcome] = []
    for pid in params.policyids:
        ok, data = await fc.fortigate_request(ctx, conn, "PUT", f"/cmdb/firewall/policy/{pid}", json_body={"status": params.new_status})
        if ok:
            items.append(BulkActionOutcome(id=pid, ok=True))
        else:
            items.append(BulkActionOutcome(id=pid, ok=False, error=data.message() if hasattr(data, "message") else str(data)))
    return ActionResult(success=True, data=BulkActionResult(title="Bulk firewall policy status change", items=items))


@chat.function(
    "audit_fortinet_estate",
    "Run a read-only health audit across all connected FortiGate/FortiManager/FortiSASE connections: disabled firewall policies with 'ALL'/'any' access, offline managed devices, expired-looking VPN tunnels, and disconnected endpoints. Same convention as Zscaler Connector's audit_tenant / Cisco Secure Access Connector's audit_secure_access.",
    action_type="write",
    data_model=AuditReport,
)
async def audit_fortinet_estate(ctx, params: AuditFortinetEstateParams) -> ActionResult:
    findings: list[AuditFinding] = []
    connections = await _load_connections(ctx)
    fg_connections = [c for c in connections if c.get("kind") == "fortigate"]
    if not fg_connections:
        findings.append(AuditFinding(id="no-fortigate", severity="info", message="No FortiGate device connected -- skipping firewall policy checks."))
    for conn in fg_connections:
        ok, data = await fc.fortigate_request(ctx, conn, "GET", "/cmdb/firewall/policy")
        if not ok:
            findings.append(AuditFinding(id=f"fg-error-{conn.get('id')}", severity="warning", message=f"Could not read policies from {conn.get('host', 'a FortiGate device')}: {data.message()}"))
            continue
        broad_allow = [
            p for p in data.get("results", [])
            if p.get("action") == "accept" and p.get("status") == "enable"
            and any(a.get("name") in ("all", "ALL") for a in p.get("srcaddr", []))
            and any(a.get("name") in ("all", "ALL") for a in p.get("dstaddr", []))
        ]
        for p in broad_allow:
            findings.append(AuditFinding(
                id=f"broad-{conn.get('id')}-{p.get('policyid')}", severity="warning",
                message=f"Policy '{p.get('name', p.get('policyid'))}' on {conn.get('host', 'device')} allows ALL source -> ALL destination -- review scope.",
            ))
        ok2, ifdata = await fc.fortigate_request(ctx, conn, "GET", "/monitor/vpn/ipsec")
        if ok2:
            down = [t for t in ifdata.get("results", []) if t.get("status") not in ("up", "connected")]
            for t in down:
                findings.append(AuditFinding(id=f"vpn-down-{conn.get('id')}-{t.get('name')}", severity="warning", message=f"VPN tunnel '{t.get('name')}' on {conn.get('host', 'device')} is down."))
    if not findings:
        findings.append(AuditFinding(id="clean", severity="info", message="No issues found across the connected Fortinet estate."))
    return ActionResult(success=True, data=AuditReport(title=f"Fortinet estate audit -- {len(findings)} finding(s)", findings=findings))
