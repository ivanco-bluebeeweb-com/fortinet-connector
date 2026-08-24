"""Fortinet Connector -- app + extension setup.

Three independent BYOK auth surfaces under one product umbrella, same
convention as Cisco Secure Access Connector's Umbrella/Meraki split:
  - FortiGate: device-level REST API token.
  - FortiManager: session-based JSON-RPC login (username/password).
  - FortiSASE: FortiCloud IAM API token.

See PREPARATION.md for the full why.
"""
from __future__ import annotations

from imperal_sdk import ChatExtension, Extension

ext = Extension(
    "fortinet-connector",
    version="0.1.0",
    display_name="Fortinet",
    icon="icon.svg",
    description=(
        "Connect your own FortiGate device(s), FortiManager (fleet "
        "management), and/or FortiSASE (cloud ZTNA/SD-WAN) tenant to "
        "manage firewall policies, address/service objects, interfaces, "
        "VPN tunnels, managed devices, policy packages, ZTNA endpoints, "
        "SASE policies, SD-WAN sites, and security events from Imperal -- "
        "plus bulk operations and a Fortinet estate health audit. Uses "
        "your own FortiGate API token, FortiManager credentials, and/or "
        "FortiSASE/FortiCloud API token -- nothing is hosted or proxied "
        "by Imperal beyond the request itself. Note: FortiAnalyzer/"
        "FortiEDR/FortiClient EMS are separate products and out of scope "
        "for this first release."
    ),
)

ext.secret("fortinet_connections", description="Stored FortiGate/FortiManager/FortiSASE connection credentials (JSON array)")

chat = ChatExtension(
    ext,
    tool_name="fortinet",
    description="Manage FortiGate, FortiManager, and FortiSASE from Imperal.",
)
