"""Panel UI -- connections list/connect forms (FortiGate + FortiManager +
FortiSASE, three independent sections) + navigation.

SIDEBAR CONTENT -- NO CARDS ANYWHERE, per ~/UI_INTERFACE_STANDARD.md's
"left sidebar, no decorated cards" rule (same convention as Cisco Secure
Access Connector's / Zscaler Connector's panels.py). Every section is a
plain ui.Stack, sections separated by ui.Divider() -- no Card border/
background/shadow anywhere in this slot. Disconnect lives only in the
"App settings" screen (panels_settings.py). The one secondary "App
settings" button is always the LAST element at the bottom of the sidebar.

PER ~/UI_INTERFACE_STANDARD.md (2026-08-21 addendum): every Input carries
its own visible label (rendered here as a sibling ui.Text caption, since
ui.Input/ui.Password/ui.Select take no label= kwarg), the placeholder text
is always contextually specific to what's being entered, the connect
form's container is stretched full-width, and its content fills that
width. The "How do I set this up?" walkthrough lives ONLY in the help
panel below -- never duplicated as static sidebar text.

Implements UI_COMPONENT_PLAN.md §1 exactly (built alongside that plan,
not after -- APP_PREPARATION_STANDARD.md §9).
"""
from __future__ import annotations

from imperal_sdk import ui

import handlers_connection as h
from app import ext


def _connect_help_panel_body() -> ui.UINode:
    return ui.Stack(direction="v", gap=3, children=[
        ui.Text("FortiGate:", variant="body"),
        ui.Text("1. Sign in to your FortiGate's web admin."),
        ui.Text("2. Go to System > Administrators > Create New > REST API Admin."),
        ui.Text("3. Copy the API token shown (shown once)."),
        ui.Divider(),
        ui.Text("FortiManager:", variant="body"),
        ui.Text("1. Use an existing FortiManager administrator username/password."),
        ui.Text("2. Optionally note which ADOM (Administrative Domain) to operate in."),
        ui.Divider(),
        ui.Text("FortiSASE:", variant="body"),
        ui.Text("1. Sign in to FortiCloud (forticloud.com)."),
        ui.Text("2. Go to Identity & Access Management > API tokens > Create."),
        ui.Text("3. Copy the token shown."),
        ui.Divider(),
        ui.Alert(
            title="Three independent connections",
            message=(
                "FortiGate, FortiManager, and FortiSASE are separate Fortinet "
                "products with separate credentials. Connect any one, two, or "
                "all three -- none is required for the others to work."
            ),
            type="info",
        ),
    ])


@ext.panel("fortinet_connect_help", slot="center", center_overlay=True)
async def fortinet_connect_help_panel(ctx) -> ui.UINode:
    return _connect_help_panel_body()


def _labeled_input(label: str, param_name: str, placeholder: str, password: bool = False) -> ui.UINode:
    field = ui.Password(param_name=param_name, placeholder=placeholder) if password else ui.Input(param_name=param_name, placeholder=placeholder)
    return ui.Stack(direction="v", gap=1, children=[ui.Text(label, variant="caption"), field])


def _fortigate_connect_form() -> ui.UINode:
    return ui.Stack(direction="v", gap=2, align="stretch", children=[
        ui.Text("Connect FortiGate", variant="heading"),
        _labeled_input("Host", "host", "https://fw01.company.com:443"),
        _labeled_input("API token", "api_token", "REST API Admin token", password=True),
        _labeled_input("Label (optional)", "label", "e.g. HQ firewall"),
        ui.Button("Connect FortiGate", variant="primary", on_click=ui.Call("connect_fortigate", {})),
    ])


def _fortimanager_connect_form() -> ui.UINode:
    return ui.Stack(direction="v", gap=2, align="stretch", children=[
        ui.Text("Connect FortiManager", variant="heading"),
        _labeled_input("Host", "host", "https://fmg.company.com"),
        _labeled_input("Username", "username", "FortiManager admin username"),
        _labeled_input("Password", "password", "FortiManager admin password", password=True),
        _labeled_input("ADOM (optional)", "adom", "root"),
        _labeled_input("Label (optional)", "label", "e.g. Main FortiManager"),
        ui.Button("Connect FortiManager", variant="primary", on_click=ui.Call("connect_fortimanager", {})),
    ])


def _fortisase_connect_form() -> ui.UINode:
    return ui.Stack(direction="v", gap=2, align="stretch", children=[
        ui.Text("Connect FortiSASE", variant="heading"),
        _labeled_input("API token", "api_token", "FortiCloud IAM API token", password=True),
        _labeled_input("Region (optional)", "region", "e.g. https://api.fortisase.forticloud.com"),
        _labeled_input("Label (optional)", "label", "e.g. Prod SASE tenant"),
        ui.Button("Connect FortiSASE", variant="primary", on_click=ui.Call("connect_fortisase", {})),
    ])


@ext.panel("fortinet_sidebar", slot="left")
async def fortinet_sidebar_panel(ctx) -> ui.UINode:
    result = await h.list_connections(ctx, h.NoParams())
    items = result.data.items if result.success and result.data else []
    if not items:
        body = ui.Stack(direction="v", gap=4, align="stretch", children=[
            ui.Empty(message="No Fortinet connections yet. Connect FortiGate, FortiManager, and/or FortiSASE below -- use any one, or all three."),
            _fortigate_connect_form(),
            ui.Divider(),
            _fortimanager_connect_form(),
            ui.Divider(),
            _fortisase_connect_form(),
        ])
    else:
        rows = [ui.Text(f"{c.title} ({c.kind})", variant="body") for c in items]
        body = ui.Stack(direction="v", gap=3, align="stretch", children=[
            ui.Text("Connections", variant="heading"),
            *rows,
            ui.Divider(),
            _fortigate_connect_form(),
            ui.Divider(),
            _fortimanager_connect_form(),
            ui.Divider(),
            _fortisase_connect_form(),
        ])
    return ui.Stack(direction="v", gap=4, align="stretch", children=[
        body,
        ui.Divider(),
        ui.Button("Help: how do I set this up?", variant="ghost", size="sm", on_click=ui.Call("__panel__fortinet_connect_help")),
        ui.Button("App settings", variant="ghost", size="sm", on_click=ui.Call("__panel__fortinet_settings")),
    ])
