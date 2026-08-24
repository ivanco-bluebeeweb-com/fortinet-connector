"""The single 'App settings' screen (center slot) -- connection management
(disconnect per FortiGate/FortiManager/FortiSASE connection) for Fortinet
Connector. Split out of panels.py per the same convention as Cisco Secure
Access Connector's / Zscaler Connector's panels_settings.py.
"""
from __future__ import annotations

from imperal_sdk import ui

from app import ext
import handlers_connection as h


def _connection_row(c) -> ui.UINode:
    return ui.Stack(direction="v", gap=1, align="start", children=[
        ui.Text(f"{c.title} ({c.kind})", variant="body"),
        ui.Text(c.detail, variant="caption"),
        ui.Button(
            "Disconnect", variant="danger", size="sm",
            on_click=ui.Call("disconnect_fortinet", {"connection_id": c.id}),
        ),
    ])


def _connections_section(items) -> ui.UINode:
    if not items:
        return ui.Stack(direction="v", gap=1, children=[
            ui.Text("Connections", variant="heading"),
            ui.Text("No FortiGate, FortiManager, or FortiSASE connections yet.", variant="caption"),
        ])
    children: list[ui.UINode] = [ui.Text("Connections", variant="heading")]
    for i, c in enumerate(items):
        if i > 0:
            children.append(ui.Divider())
        children.append(_connection_row(c))
    return ui.Stack(direction="v", gap=2, align="start", children=children)


@ext.panel("fortinet_settings", slot="center", center_overlay=True)
async def fortinet_settings_panel(ctx) -> ui.UINode:
    result = await h.list_connections(ctx, h.NoParams())
    items = result.data.items if result.success and result.data else []
    return ui.Stack(direction="v", gap=4, align="stretch", children=[
        ui.Text("App settings", variant="heading"),
        _connections_section(items),
    ])
