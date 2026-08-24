"""Entrypoint for the web-kernel and CLI tools (imperal validate/build).

Sets up sys.path, purges stale module cache, then imports ext/chat and all
handler modules so their decorators register on the same Extension instance
-- same pattern as Cisco Secure Access Connector's / Zscaler Connector's
main.py.
"""

import os
import sys

_EXT_DIR = os.path.dirname(os.path.abspath(__file__))
if _EXT_DIR not in sys.path:
    sys.path.insert(0, _EXT_DIR)

_LOCAL = (
    "app", "schemas", "fortinet_client",
    "handlers_connection", "handlers_fortigate", "handlers_fortimanager",
    "handlers_fortisase", "handlers_bulk_audit",
    "panels", "panels_center", "panels_settings",
)
for _mod in _LOCAL:
    sys.modules.pop(_mod, None)

from app import ext, chat  # noqa: E402,F401
import handlers_connection  # noqa: E402,F401
import handlers_fortigate  # noqa: E402,F401
import handlers_fortimanager  # noqa: E402,F401
import handlers_fortisase  # noqa: E402,F401
import handlers_bulk_audit  # noqa: E402,F401
import panels  # noqa: E402,F401
import panels_center  # noqa: E402,F401
import panels_settings  # noqa: E402,F401
